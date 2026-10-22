import { normalizeEmail } from '../security/email.js';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { and, desc, eq, gt, inArray, isNotNull, isNull, lt, or, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { memberRoles, roles, users, workspaceInvitations, workspaceMembers, workspaces } from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { loadWorkspaceAuthorizationSnapshot } from './authorization.service.js';
import { assertRoleOverridesHeld, loadRoleOverrides } from './role.service.js';
import {
  INVITATION_RETENTION_DAYS,
  MAX_ACTIVE_INVITATIONS_PER_WORKSPACE,
  MAX_ROLE_ASSIGNMENTS_PER_MEMBER,
  MAX_RETAINED_INVITATIONS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERS,
  MAX_WORKSPACE_MEMBERSHIPS_PER_USER,
} from '../security/limits.js';

export function normalizeInvitationEmail(email: string): string {
  return normalizeEmail(email);
}

export function hashInvitationToken(token: string): string {
  // Tokens carry 256 bits of CSPRNG entropy, so a domain-separated digest is
  // sufficient for lookup while keeping JWT-key rotation independent from
  // invitation validity.
  return createHash('sha256')
    .update('alparts-workspace-invitation-v1\0', 'utf8')
    .update(token, 'utf8')
    .digest('hex');
}

function legacyInvitationTokenHash(token: string): string {
  return createHmac('sha256', config.jwt.secret)
    .update('alparts-workspace-invitation-v1\0', 'utf8')
    .update(token, 'utf8')
    .digest('hex');
}

export function assertValidInvitationLifetime(expiresInSeconds: number): void {
  if (
    !Number.isSafeInteger(expiresInSeconds)
    || expiresInSeconds < 300
    || expiresInSeconds > 30 * 24 * 60 * 60
  ) throw new Error('INVALID_INVITATION_EXPIRY');
}

/**
 * Cheap, non-authoritative admission before bcrypt. Consumption repeats every
 * check under the workspace/invitation locks, so this optimization never turns
 * a stale preflight result into an accepted invitation.
 */
export async function preflightRegistrationInvitation(
  normalizedEmail: string,
  token: string,
  bootstrap: boolean,
): Promise<void> {
  if (bootstrap) {
    const anyUser = await db.query.users.findFirst({ columns: { id: true } });
    if (anyUser) throw new Error('INVALID_INVITATION');
    return;
  }
  if (token.length < 32 || token.length > 512) throw new Error('INVALID_INVITATION');
  const candidate = await db.query.workspaceInvitations.findFirst({
    where: inArray(workspaceInvitations.tokenHash, [hashInvitationToken(token), legacyInvitationTokenHash(token)]),
  });
  const now = new Date();
  if (
    !candidate
    || candidate.usedAt
    || candidate.revokedAt
    || candidate.expiresAt <= now
    || (candidate.email && candidate.email !== normalizedEmail)
    || !candidate.roleId
  ) throw new Error('INVALID_INVITATION');
  const role = await db.query.roles.findFirst({
    columns: { id: true, name: true },
    where: and(eq(roles.id, candidate.roleId), eq(roles.workspaceId, candidate.workspaceId)),
  });
  if (!role || role.name === 'Owner') throw new Error('INVALID_INVITATION');
}

export async function createInvitation(
  workspaceId: string,
  actorId: string,
  input: { email?: string; roleId?: string; expiresInSeconds: number },
  revalidateStepUp?: (tx: any) => Promise<void>,
) {
  assertValidInvitationLifetime(input.expiresInSeconds);
  const token = randomBytes(32).toString('base64url');
  const tokenHash = hashInvitationToken(token);
  const email = input.email ? normalizeInvitationEmail(input.email) : null;
  const expiresAt = new Date(Date.now() + input.expiresInSeconds * 1000);
  const invitation = await auditedTransaction(async (transaction) => {
    if (revalidateStepUp) await revalidateStepUp(transaction);
    await lockWorkspace(transaction, workspaceId);
    const role = await getInvitationRole(transaction, workspaceId, actorId, input.roleId);
    const now = new Date();
    const retentionCutoff = new Date(now.getTime() - INVITATION_RETENTION_DAYS * 24 * 60 * 60 * 1_000);
    const pruned = await transaction.delete(workspaceInvitations).where(and(
      eq(workspaceInvitations.workspaceId, workspaceId),
      lt(workspaceInvitations.createdAt, retentionCutoff),
      or(
        isNotNull(workspaceInvitations.usedAt),
        isNotNull(workspaceInvitations.revokedAt),
        lt(workspaceInvitations.expiresAt, now),
      ),
    )).returning({ id: workspaceInvitations.id });
    const retained = await transaction.query.workspaceInvitations.findMany({
      columns: { id: true },
      where: eq(workspaceInvitations.workspaceId, workspaceId),
      limit: MAX_RETAINED_INVITATIONS_PER_WORKSPACE + 1,
    });
    if (retained.length >= MAX_RETAINED_INVITATIONS_PER_WORKSPACE) {
      throw new Error('INVITATION_RETENTION_LIMIT_REACHED');
    }
    const active = await transaction.query.workspaceInvitations.findMany({
      columns: { id: true },
      where: and(
        eq(workspaceInvitations.workspaceId, workspaceId),
        isNull(workspaceInvitations.usedAt),
        isNull(workspaceInvitations.revokedAt),
        gt(workspaceInvitations.expiresAt, now),
      ),
      limit: MAX_ACTIVE_INVITATIONS_PER_WORKSPACE + 1,
    });
    if (active.length >= MAX_ACTIVE_INVITATIONS_PER_WORKSPACE) {
      throw new Error('INVITATION_ACTIVE_LIMIT_REACHED');
    }
    const [created] = await transaction.insert(workspaceInvitations).values({
      workspaceId,
      roleId: role.id,
      tokenHash,
      email,
      createdBy: actorId,
      expiresAt,
    }).returning();
    return { created, role, prunedCount: pruned.length };
  }, ({ created, role, prunedCount }) => ({
    actorId,
    action: 'workspace.invitation.create',
    targetType: 'workspace_invitation',
    targetId: created.id,
    details: {
      workspaceId,
      roleId: role.id,
      emailBound: Boolean(email),
      expiresAt: expiresAt.toISOString(),
      prunedTerminalInvitations: prunedCount,
    },
  }));
  return { ...formatInvitation(invitation.created, invitation.role), token };
}

export async function listInvitations(workspaceId: string) {
  const rows = await db.query.workspaceInvitations.findMany({
    columns: {
      id: true,
      workspaceId: true,
      roleId: true,
      email: true,
      createdBy: true,
      expiresAt: true,
      usedAt: true,
      usedBy: true,
      revokedAt: true,
      revokedBy: true,
      createdAt: true,
    },
    where: eq(workspaceInvitations.workspaceId, workspaceId),
    orderBy: [desc(workspaceInvitations.createdAt), desc(workspaceInvitations.id)],
    limit: MAX_RETAINED_INVITATIONS_PER_WORKSPACE + 1,
  });
  if (rows.length > MAX_RETAINED_INVITATIONS_PER_WORKSPACE) {
    throw new Error('INVITATION_INVARIANT_EXCEEDED');
  }
  const roleIds = [...new Set(rows.flatMap((row) => row.roleId ? [row.roleId] : []))];
  const roleRows = roleIds.length > 0
    ? await db.query.roles.findMany({
      where: and(eq(roles.workspaceId, workspaceId), inArray(roles.id, roleIds)),
    })
    : [];
  const rolesById = new Map(roleRows.map((role) => [role.id, role]));
  return rows.map((row) => formatInvitation(row, row.roleId ? rolesById.get(row.roleId) : undefined));
}

export async function revokeInvitation(workspaceId: string, invitationId: string, actorId: string, revalidateStepUp?: (tx: any) => Promise<void>) {
  const invitation = await auditedTransaction(async (transaction) => {
    if (revalidateStepUp) await revalidateStepUp(transaction);
    await lockWorkspace(transaction, workspaceId);
    // Middleware authorization is only a hint. Recheck after acquiring the
    // workspace lock so a concurrent role revocation cannot race this write.
    await getInvitationRole(transaction, workspaceId, actorId);
    await transaction.execute(sql`
      select 1 from ${workspaceInvitations}
      where ${workspaceInvitations.id} = ${invitationId}
        and ${workspaceInvitations.workspaceId} = ${workspaceId}
      for update
    `);
    const existing = await transaction.query.workspaceInvitations.findFirst({
      where: and(eq(workspaceInvitations.id, invitationId), eq(workspaceInvitations.workspaceId, workspaceId)),
    });
    if (!existing) throw new Error('INVITATION_NOT_FOUND');
    const now = new Date();
    if (existing.usedAt || existing.revokedAt || existing.expiresAt <= now) throw new Error('INVITATION_NOT_ACTIVE');
    const [revoked] = await transaction.update(workspaceInvitations)
      .set({ revokedAt: now, revokedBy: actorId })
      .where(and(
        eq(workspaceInvitations.id, invitationId),
        eq(workspaceInvitations.workspaceId, workspaceId),
        isNull(workspaceInvitations.usedAt),
        isNull(workspaceInvitations.revokedAt),
        gt(workspaceInvitations.expiresAt, now),
      ))
      .returning();
    if (!revoked) throw new Error('INVITATION_NOT_ACTIVE');
    return revoked;
  }, () => ({
    actorId,
    action: 'workspace.invitation.revoke',
    targetType: 'workspace_invitation',
    targetId: invitationId,
    details: { workspaceId },
  }));
  return formatInvitation(invitation);
}

export async function acceptInvitation(userId: string, token: string) {
  const user = await db.query.users.findFirst({
    columns: { email: true },
    where: eq(users.id, userId),
  });
  if (!user) throw new Error('INVALID_INVITATION');
  let consumed;
  try {
    consumed = await auditedTransaction(
      (transaction) => consumeInvitation(
        transaction,
        token,
        normalizeInvitationEmail(user.email),
        userId,
      ),
      (result) => ({
        actorId: userId,
        action: 'workspace.invitation.use',
        targetType: 'workspace_invitation',
        targetId: result.invitationId,
        details: { workspaceId: result.workspaceId, roleId: result.roleId, existingAccount: true },
      }),
    );
  } catch (error: any) {
    if (error?.code === '23505') throw new Error('INVALID_INVITATION');
    throw error;
  }
  return consumed;
}

export async function consumeInvitation(
  transaction: any,
  token: string,
  normalizedEmail: string,
  userId: string,
) {
  const claim = await lockInvitationForConsumption(transaction, token, normalizedEmail);
  return consumeLockedInvitation(transaction, claim, userId);
}

export async function lockInvitationForConsumption(
  transaction: any,
  token: string,
  normalizedEmail: string,
) {
  if (token.length < 32 || token.length > 512) throw new Error('INVALID_INVITATION');
  const tokenHashes = [hashInvitationToken(token), legacyInvitationTokenHash(token)];
  const candidate = await transaction.query.workspaceInvitations.findFirst({
    where: inArray(workspaceInvitations.tokenHash, tokenHashes),
  });
  if (!candidate) throw new Error('INVALID_INVITATION');
  // All membership admissions serialize on the workspace row. Discover the
  // high-entropy token first, then re-read it under the canonical lock order.
  await lockWorkspace(transaction, candidate.workspaceId);
  // The legacy candidate preserves already-issued invitations while new rows
  // no longer depend on the JWT signing-key lifecycle.
  await transaction.execute(sql`select 1 from ${workspaceInvitations} where ${inArray(workspaceInvitations.tokenHash, tokenHashes)} for update`);
  const invitation = await transaction.query.workspaceInvitations.findFirst({
    where: inArray(workspaceInvitations.tokenHash, tokenHashes),
  });
  const now = new Date();
  if (
    !invitation
    || invitation.usedAt
    || invitation.revokedAt
    || invitation.expiresAt <= now
    || (invitation.email && invitation.email !== normalizedEmail)
    || !invitation.roleId
  ) {
    throw new Error('INVALID_INVITATION');
  }
  const role = await transaction.query.roles.findFirst({
    where: and(eq(roles.id, invitation.roleId), eq(roles.workspaceId, invitation.workspaceId)),
  });
  if (!role || role.name === 'Owner') throw new Error('INVALID_INVITATION');
  await assertCreatorMayStillInvite(transaction, invitation, role);
  return { invitation, role, now };
}

export async function consumeLockedInvitation(
  transaction: any,
  claim: Awaited<ReturnType<typeof lockInvitationForConsumption>>,
  userId: string,
) {
  const { invitation, role, now } = claim;
  // Canonical admission order is workspace row -> account membership lock.
  // Invitations for separate workspaces therefore serialize only when they
  // would change the same account's bounded membership set.
  await transaction.execute(
    sql`select pg_advisory_xact_lock(hashtext(${`workspace-memberships:${userId}`})::bigint)`,
  );
  const userMemberships = await transaction.query.workspaceMembers.findMany({
    columns: { id: true },
    where: eq(workspaceMembers.userId, userId),
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  });
  if (userMemberships.length >= MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
    throw new Error('WORKSPACE_MEMBERSHIP_LIMIT_REACHED');
  }
  const currentMembers = await transaction.query.workspaceMembers.findMany({
    columns: { id: true },
    where: eq(workspaceMembers.workspaceId, invitation.workspaceId),
    limit: MAX_WORKSPACE_MEMBERS + 1,
  });
  if (currentMembers.length >= MAX_WORKSPACE_MEMBERS) throw new Error('WORKSPACE_MEMBER_LIMIT');
  const [member] = await transaction.insert(workspaceMembers).values({
    workspaceId: invitation.workspaceId,
    userId,
  }).returning();
  await transaction.insert(memberRoles).values({ memberId: member.id, roleId: role.id });
  const consumed = await transaction.update(workspaceInvitations)
    .set({ usedAt: now, usedBy: userId })
    .where(and(
      eq(workspaceInvitations.id, invitation.id),
      isNull(workspaceInvitations.usedAt),
      isNull(workspaceInvitations.revokedAt),
      gt(workspaceInvitations.expiresAt, now),
    ))
    .returning({ id: workspaceInvitations.id });
  if (consumed.length !== 1) throw new Error('INVALID_INVITATION');
  return { invitationId: invitation.id, workspaceId: invitation.workspaceId, roleId: role.id };
}

async function getInvitationRole(store: any, workspaceId: string, actorId: string, requestedRoleId?: string) {
  const actor = await loadInviter(store, workspaceId, actorId);
  if (!actor || (actor.permissions & Permissions.MANAGE_MEMBERS) !== Permissions.MANAGE_MEMBERS) {
    throw new Error('NOT_AUTHORIZED');
  }

  const role = requestedRoleId
    ? await store.query.roles.findFirst({ where: and(eq(roles.id, requestedRoleId), eq(roles.workspaceId, workspaceId)) })
    : await store.query.roles.findFirst({ where: and(eq(roles.workspaceId, workspaceId), eq(roles.name, 'Member')) });
  if (
    !role
    || role.name === 'Owner'
    || !mayGrantInvitationRole(actor, role, Boolean(requestedRoleId))
    || !(await inviterHoldsRoleOverrides(store, workspaceId, actorId, actor, role))
  ) {
    throw new Error('INVALID_INVITATION_ROLE');
  }
  return role;
}

/**
 * Creation checks the creator's authority once, but an invitation outlives it.
 * It is checked again when the invitation is used, so a member who was removed
 * or lost the right to invite does not keep admitting people. The owner
 * always may. An invitation for the default role is one its creator could
 * still make without naming a role; for any other role the creator must also
 * still hold the bits its overrides allow.
 */
async function assertCreatorMayStillInvite(
  store: any,
  invitation: { workspaceId: string; createdBy: string },
  role: { id: string; name: string; permissions: number; position: number },
) {
  const creator = await loadInviter(store, invitation.workspaceId, invitation.createdBy);
  if (!creator) throw new Error('INVALID_INVITATION');
  if (creator.isOwner) return;
  if (
    (creator.permissions & Permissions.MANAGE_MEMBERS) !== Permissions.MANAGE_MEMBERS
    || !mayGrantInvitationRole(creator, role, role.name !== 'Member')
    || !(await inviterHoldsRoleOverrides(store, invitation.workspaceId, invitation.createdBy, creator, role))
  ) throw new Error('INVALID_INVITATION');
}

export interface Inviter {
  isOwner: boolean;
  /** Union of the permissions of the roles held. */
  permissions: number;
  /** Highest position among the roles held, -1 for none. */
  highestPosition: number;
}

/** The member's authority in the workspace, or null when they are not a member. */
async function loadInviter(store: any, workspaceId: string, userId: string): Promise<Inviter | null> {
  const workspace = await store.query.workspaces.findFirst({
    columns: { ownerId: true },
    where: eq(workspaces.id, workspaceId),
  });
  if (!workspace) throw new Error('WORKSPACE_NOT_FOUND');
  const member = await store.query.workspaceMembers.findFirst({
    where: and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)),
  });
  if (!member) return null;
  const assignments = await store.query.memberRoles.findMany({
    where: eq(memberRoles.memberId, member.id),
    with: { role: true },
    limit: MAX_ROLE_ASSIGNMENTS_PER_MEMBER + 1,
  });
  if (assignments.length > MAX_ROLE_ASSIGNMENTS_PER_MEMBER) {
    throw new Error('ROLE_ASSIGNMENT_INVARIANT_EXCEEDED');
  }
  const heldRoles = assignments
    .map((assignment: any) => assignment.role)
    .filter((role: any) => role?.workspaceId === workspaceId);
  return {
    isOwner: workspace.ownerId === userId,
    permissions: heldRoles.reduce((mask: number, role: any) => mask | role.permissions, 0),
    highestPosition: Math.max(-1, ...heldRoles.map((role: any) => role.position)),
  };
}

/**
 * Whether a member who may invite can hand out this role: the owner any, others
 * only roles whose permissions they all hold. Naming a role also needs
 * MANAGE_ROLES and a role below their highest.
 */
export function mayGrantInvitationRole(
  inviter: Inviter,
  role: { permissions: number; position: number },
  roleNamed: boolean,
): boolean {
  if (inviter.isOwner) return true;
  if ((role.permissions & ~inviter.permissions) !== 0) return false;
  return !roleNamed || (
    role.position < inviter.highestPosition
    && (inviter.permissions & Permissions.MANAGE_ROLES) === Permissions.MANAGE_ROLES
  );
}

/**
 * Whoever holds a role gets the bits that the category and channel overrides
 * written for it allow, so handing out a role other than the default one takes
 * the bits that assigning it to a member takes. The default role is what an
 * invitation without a role hands out, so a manager who may only add members
 * still can, and the owner holds every bit.
 */
export async function inviterHoldsRoleOverrides(
  store: any,
  workspaceId: string,
  userId: string,
  inviter: Inviter,
  role: { id: string; name: string },
): Promise<boolean> {
  if (inviter.isOwner || role.name === 'Member') return true;
  const snapshot = await loadWorkspaceAuthorizationSnapshot(store, workspaceId);
  if (!snapshot) throw new Error('WORKSPACE_NOT_FOUND');
  const overrides = await loadRoleOverrides(store, workspaceId, role.id);
  try {
    assertRoleOverridesHeld(snapshot, userId, overrides, 'assign');
    return true;
  } catch (error: any) {
    if (error?.message === 'PERMISSION_ESCALATION' || error?.message === 'NOT_AUTHORIZED') return false;
    throw error;
  }
}

async function lockWorkspace(store: any, workspaceId: string) {
  const locked = await store.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
  if (locked.rowCount === 0) throw new Error('WORKSPACE_NOT_FOUND');
}

function formatInvitation(invitation: any, role?: any) {
  const now = Date.now();
  const status = invitation.usedAt
    ? 'used'
    : invitation.revokedAt
      ? 'revoked'
      : invitation.expiresAt.getTime() <= now
        ? 'expired'
        : 'active';
  return {
    id: invitation.id,
    workspaceId: invitation.workspaceId,
    role: role ? {
      id: role.id,
      name: role.name,
      permissions: role.permissions.toString(),
      position: role.position,
    } : null,
    email: invitation.email,
    createdBy: invitation.createdBy,
    expiresAt: invitation.expiresAt.toISOString(),
    usedAt: invitation.usedAt?.toISOString() || null,
    usedBy: invitation.usedBy,
    revokedAt: invitation.revokedAt?.toISOString() || null,
    revokedBy: invitation.revokedBy,
    createdAt: invitation.createdAt.toISOString(),
    status,
  };
}
