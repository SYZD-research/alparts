import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { and, eq, gt, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { sessions, users } from '../db/schema.js';
import { config } from '../config/index.js';
import { audit, auditedTransaction, type AuditEntry } from '../middleware/audit.js';
import { hashSessionToken } from '../security/session.js';
import { matchesSecret } from '../security/cookies.js';
import { consumeLockedInvitation, lockInvitationForConsumption } from './invitation.service.js';

const SALT_ROUNDS = 12;
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('alparts-invalid-credential-sentinel', SALT_ROUNDS);

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function assertPasswordSupported(password: string): void {
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 12 || bytes > 72) throw new Error('INVALID_PASSWORD_LENGTH');
}

export async function register(email: string, password: string, displayName: string, inviteToken: string) {
  assertPasswordSupported(password);
  const normalizedEmail = normalizeEmail(email);
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const bootstrap = matchesSecret(inviteToken, config.auth.registrationInviteSecret);
  let result;
  try {
    result = await auditedTransaction(async (transaction) => {
      if (bootstrap) {
        // The deployment secret exists only to create the first account. Normal
        // registration must use a one-time workspace invitation.
        await transaction.execute(sql`select pg_advisory_xact_lock(1095520322)`);
        const anyUser = await transaction.query.users.findFirst({ columns: { id: true } });
        if (anyUser) throw new Error('INVALID_INVITATION');
      }
      const invitationClaim = bootstrap
        ? null
        : await lockInvitationForConsumption(transaction, inviteToken, normalizedEmail);
      const existing = await transaction.query.users.findFirst({
        columns: { id: true },
        where: eq(users.email, normalizedEmail),
      });
      if (existing) throw new Error('EMAIL_EXISTS');

      const [user] = await transaction.insert(users).values({
        email: normalizedEmail,
        passwordHash,
        displayName: displayName.trim(),
      }).returning();
      const invitation = invitationClaim
        ? await consumeLockedInvitation(transaction, invitationClaim, user.id)
        : null;
      return { user, invitation };
    }, (committed) => {
      const entries: AuditEntry[] = [{
        actorId: committed.user.id,
        action: 'user.register',
        targetType: 'user',
        targetId: committed.user.id,
        details: { bootstrap, workspaceInvitation: Boolean(committed.invitation) },
      }];
      if (committed.invitation) {
        entries.push({
          actorId: committed.user.id,
          action: 'workspace.invitation.use',
          targetType: 'workspace_invitation',
          targetId: committed.invitation.invitationId,
          details: { workspaceId: committed.invitation.workspaceId, roleId: committed.invitation.roleId },
        });
      }
      return entries;
    });
  } catch (error: any) {
    if (error?.code === '23505') throw new Error('EMAIL_EXISTS');
    throw error;
  }
  return publicUser(result.user);
}

export async function login(email: string, password: string, deviceInfo?: Record<string, unknown>) {
  const normalizedEmail = normalizeEmail(email);
  const user = await db.query.users.findFirst({ where: eq(users.email, normalizedEmail) });
  const valid = await bcrypt.compare(password, user?.passwordHash || DUMMY_PASSWORD_HASH);
  if (!user || !valid) {
    await audit({ action: 'user.login.failed', targetType: 'user' });
    throw new Error('INVALID_CREDENTIALS');
  }

  const sessionId = randomUUID();
  const expiresAt = new Date(Date.now() + config.jwt.expiresInSeconds * 1000);
  const token = jwt.sign(
    { sid: sessionId },
    config.jwt.secret,
    {
      algorithm: 'HS256',
      subject: user.id,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      expiresIn: config.jwt.expiresInSeconds,
      jwtid: randomUUID(),
    },
  );

  await auditedTransaction(async (transaction) => {
    await transaction.insert(sessions).values({
      id: sessionId,
      userId: user.id,
      tokenHash: hashSessionToken(token),
      deviceInfo: deviceInfo || null,
      expiresAt,
    });
    await transaction.update(users).set({ updatedAt: new Date() }).where(eq(users.id, user.id));
    return { sessionId };
  }, () => ({ actorId: user.id, action: 'user.login', targetType: 'user', targetId: user.id }));

  return { token, user: publicUser(user) };
}

export async function logout(sessionId: string, actorId: string) {
  await auditedTransaction(async (transaction) => {
    const removed = await transaction.delete(sessions)
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, actorId)))
      .returning({ id: sessions.id });
    return { removed: removed.length === 1 };
  }, (result) => ({
    actorId,
    action: 'user.logout',
    targetType: 'session',
    targetId: sessionId,
    details: { removed: result.removed },
  }));
}

export async function listSessions(userId: string, currentSessionId: string) {
  const rows = await db.query.sessions.findMany({
    where: and(eq(sessions.userId, userId), gt(sessions.expiresAt, new Date())),
    orderBy: (table, { desc }) => [desc(table.createdAt)],
  });
  return rows.map((session) => ({
    id: session.id,
    deviceId: session.deviceId,
    deviceInfo: session.deviceInfo,
    createdAt: session.createdAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    current: session.id === currentSessionId,
  }));
}

export async function revokeSession(userId: string, sessionId: string): Promise<boolean> {
  const result = await auditedTransaction(async (transaction) => {
    const removed = await transaction.delete(sessions)
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId)))
      .returning({ id: sessions.id });
    return { removed: removed.length === 1 };
  }, (committed) => ({
    actorId: userId,
    action: 'session.revoke',
    targetType: 'session',
    targetId: sessionId,
    details: { removed: committed.removed },
  }));
  return result.removed;
}

export async function revokeAllSessions(userId: string): Promise<string[]> {
  return auditedTransaction(async (transaction) => {
    const removed = await transaction.delete(sessions)
      .where(eq(sessions.userId, userId))
      .returning({ id: sessions.id });
    return removed.map((session: { id: string }) => session.id);
  }, (removedIds) => ({
    actorId: userId,
    action: 'session.revoke_all',
    targetType: 'user',
    targetId: userId,
    details: { count: removedIds.length },
  }));
}

export async function getUserById(userId: string) {
  const user = await db.query.users.findFirst({ where: eq(users.id, userId) });
  return user ? publicUser(user) : null;
}

export async function assertCurrentPassword(store: any, userId: string, password: string): Promise<void> {
  const user = await store.query.users.findFirst({
    columns: { passwordHash: true },
    where: eq(users.id, userId),
  });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) throw new Error('INVALID_CREDENTIALS');
}

function publicUser(user: typeof users.$inferSelect) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    createdAt: user.createdAt.toISOString(),
  };
}
