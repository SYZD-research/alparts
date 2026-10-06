import { randomUUID } from 'node:crypto';
import { and, desc, eq, inArray, sql } from 'drizzle-orm';
import { Permissions, type MemberProfile, type OwnProfile, type ProfileAppealStatus, type ProfileFlagEntry } from '@alparts/shared';
import { db } from '../db/index.js';
import { profileFlags, users, workspaceMembers, workspaces } from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { MAX_WORKSPACE_MEMBERS, MAX_WORKSPACE_MEMBERSHIPS_PER_USER } from '../security/limits.js';
import { MAX_AVATAR_BYTES, sanitizeAvatarPng } from '../security/profile-input.js';
import {
  getWorkspaceAuthorizationFromSnapshot,
  loadWorkspaceAuthorizationSnapshot,
  lockWorkspaceForAuthorization,
  type WorkspaceAuthorizationSnapshot,
} from './authorization.service.js';
import { putStoredObject, readStoredObject, removeStoredObjectBestEffort } from './object-storage.js';

function avatarPath(userId: string, version: string): string {
  return `/api/users/${userId}/avatar/${version}`;
}

/** Workspaces the user belongs to; profile changes are announced there. */
export async function workspaceIdsOf(userId: string): Promise<string[]> {
  const rows = await db.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  });
  if (rows.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  return rows.map((row) => row.workspaceId);
}

/**
 * A save that changes nothing leaves profileUpdatedAt alone: that timestamp is
 * what allows a warned user to ask for the warning to be lifted. It is taken
 * from the database clock, like profile_flags.flagged_at, so the two compare
 * without depending on the application host's clock.
 */
export async function updateProfile(userId: string, input: { displayName?: string; bio?: string }) {
  const bio = input.bio === undefined ? undefined : input.bio.length > 0 ? input.bio : null;
  const current = await db.query.users.findFirst({ columns: { displayName: true, bio: true }, where: eq(users.id, userId) });
  if (!current) throw new Error('USER_NOT_FOUND');
  if ((input.displayName === undefined || input.displayName === current.displayName)
    && (bio === undefined || bio === current.bio)) {
    return;
  }
  await auditedTransaction(async (tx) => {
    const [locked] = await tx.select({ displayName: users.displayName, bio: users.bio })
      .from(users).where(eq(users.id, userId)).for('update');
    if (!locked) throw new Error('USER_NOT_FOUND');
    // The preflight read is only an optimization. Another save and a warning
    // can commit before this transaction acquires the row.
    if ((input.displayName === undefined || input.displayName === locked.displayName)
      && (bio === undefined || bio === locked.bio)) return null;
    const set: Partial<typeof users.$inferInsert> = { profileUpdatedAt: sql`now()` as unknown as Date, updatedAt: new Date() };
    if (input.displayName !== undefined) set.displayName = input.displayName;
    if (bio !== undefined) set.bio = bio;
    const updated = await tx.update(users).set(set).where(eq(users.id, userId)).returning({ id: users.id });
    if (updated.length !== 1) throw new Error('USER_NOT_FOUND');
    return null;
  }, () => ({ actorId: userId, action: 'user.profile.update', targetType: 'user', targetId: userId }));
}

/** Uploading the picture already in use changes nothing (sanitized bytes are canonical). */
async function isCurrentAvatar(userId: string, image: Buffer, store = db): Promise<string | null> {
  const user = await store.query.users.findFirst({ columns: { avatarObjectKey: true, avatarUrl: true }, where: eq(users.id, userId) });
  if (!user) throw new Error('USER_NOT_FOUND');
  if (!user.avatarObjectKey || !user.avatarUrl) return null;
  try {
    const stored = await readStoredObject(user.avatarObjectKey, MAX_AVATAR_BYTES);
    // Previously stored avatars may use different PNG row filters. Compare
    // canonical pixels for those too, without requiring a storage migration.
    return sanitizeAvatarPng(stored).equals(image) ? user.avatarUrl : null;
  } catch {
    return null;
  }
}

/**
 * The avatar key the row settles on. FOR UPDATE waits for a transaction that
 * is still committing on another connection, so the answer is final. Returns
 * undefined when the row cannot be read.
 */
async function settledAvatarKey(userId: string): Promise<string | null | undefined> {
  try {
    return await db.transaction(async (tx) => {
      const [row] = await tx.select({ key: users.avatarObjectKey }).from(users).where(eq(users.id, userId)).for('update');
      return row ? row.key : null;
    });
  } catch {
    return undefined;
  }
}

export async function setAvatar(userId: string, upload: Buffer) {
  const image = sanitizeAvatarPng(upload);
  const unchanged = await isCurrentAvatar(userId, image);
  if (unchanged) return { avatarUrl: unchanged };
  const version = randomUUID();
  const objectKey = `avatars/v1/${userId}/${version}`;
  await putStoredObject(objectKey, image);
  let previousKey: string | null = null;
  let savedUrl = avatarPath(userId, version);
  try {
    savedUrl = await auditedTransaction(async (tx) => {
      const [current] = await tx.select({ key: users.avatarObjectKey }).from(users).where(eq(users.id, userId)).for('update');
      if (!current) throw new Error('USER_NOT_FOUND');
      const unchanged = await isCurrentAvatar(userId, image, tx as typeof db);
      if (unchanged) return unchanged;
      previousKey = current.key;
      await tx.update(users).set({
        avatarObjectKey: objectKey,
        avatarUrl: avatarPath(userId, version),
        profileUpdatedAt: sql`now()` as unknown as Date,
        updatedAt: new Date(),
      }).where(eq(users.id, userId));
      return avatarPath(userId, version);
    }, () => ({ actorId: userId, action: 'user.avatar.update', targetType: 'user', targetId: userId }));
  } catch (error) {
    // An error does not prove the commit failed (the connection can drop
    // after COMMIT). Delete the new object only when the row is known not to
    // reference it: a referenced missing object would break the avatar and
    // stop backups. When the row cannot be read, the object is left behind.
    const referenced = await settledAvatarKey(userId);
    if (referenced === objectKey) {
      if (previousKey) await removeStoredObjectBestEffort(previousKey);
      return { avatarUrl: avatarPath(userId, version) };
    }
    if (referenced !== undefined) await removeStoredObjectBestEffort(objectKey);
    throw error;
  }
  if (savedUrl !== avatarPath(userId, version)) await removeStoredObjectBestEffort(objectKey);
  if (previousKey) await removeStoredObjectBestEffort(previousKey);
  return { avatarUrl: savedUrl };
}

export async function removeAvatar(userId: string) {
  const current = await db.query.users.findFirst({ columns: { avatarObjectKey: true }, where: eq(users.id, userId) });
  if (!current) throw new Error('USER_NOT_FOUND');
  if (!current.avatarObjectKey) return;
  let previousKey: string | null = null;
  await auditedTransaction(async (tx) => {
    const [locked] = await tx.select({ key: users.avatarObjectKey }).from(users).where(eq(users.id, userId)).for('update');
    if (!locked) throw new Error('USER_NOT_FOUND');
    if (!locked.key) return null;
    previousKey = locked.key;
    await tx.update(users).set({ avatarObjectKey: null, avatarUrl: null, profileUpdatedAt: sql`now()` as unknown as Date, updatedAt: new Date() })
      .where(eq(users.id, userId));
    return null;
  }, () => ({ actorId: userId, action: 'user.avatar.remove', targetType: 'user', targetId: userId }));
  if (previousKey) await removeStoredObjectBestEffort(previousKey);
}

/** Avatars are visible to the user and to anyone sharing a workspace with them. */
export async function readAvatar(requesterId: string, userId: string, version: string): Promise<Buffer | null> {
  const user = await db.query.users.findFirst({ columns: { avatarObjectKey: true }, where: eq(users.id, userId) });
  if (!user?.avatarObjectKey || user.avatarObjectKey !== `avatars/v1/${userId}/${version}`) return null;
  if (requesterId !== userId && !await sharesWorkspace(requesterId, userId)) return null;
  return readStoredObject(user.avatarObjectKey, MAX_AVATAR_BYTES);
}

async function sharesWorkspace(left: string, right: string): Promise<boolean> {
  const rows = await db.execute(sql`
    select 1 from ${workspaceMembers} a
    join ${workspaceMembers} b on a.workspace_id = b.workspace_id
    where a.user_id = ${left} and b.user_id = ${right}
    limit 1
  `);
  return rows.rows.length > 0;
}

function canManageFlags(snapshot: WorkspaceAuthorizationSnapshot, actorId: string): boolean {
  if (snapshot.ownerId === actorId) return true;
  const actor = getWorkspaceAuthorizationFromSnapshot(snapshot, actorId);
  return Boolean(actor && (actor.permissionMask & Permissions.MANAGE_MEMBERS) === Permissions.MANAGE_MEMBERS);
}

function rank(snapshot: WorkspaceAuthorizationSnapshot, userId: string): number {
  if (snapshot.ownerId === userId) return Number.POSITIVE_INFINITY;
  const member = getWorkspaceAuthorizationFromSnapshot(snapshot, userId);
  return Math.max(-1, ...(member?.roles ?? []).map((role: { position: number }) => role.position));
}

/** MANAGE_MEMBERS (or owner) and, like member removal, a strictly higher rank. */
function assertFlagAuthority(snapshot: WorkspaceAuthorizationSnapshot, actorId: string, userId: string) {
  if (!snapshot.membersByUserId.has(userId)) throw new Error('MEMBER_NOT_FOUND');
  if (!canManageFlags(snapshot, actorId)) throw new Error('NOT_AUTHORIZED');
  if (userId === actorId || userId === snapshot.ownerId) throw new Error('MEMBER_HIERARCHY');
  if (snapshot.ownerId !== actorId && rank(snapshot, userId) >= rank(snapshot, actorId)) throw new Error('MEMBER_HIERARCHY');
}

async function requireSnapshot(store: any, workspaceId: string) {
  const snapshot = await loadWorkspaceAuthorizationSnapshot(store, workspaceId, []);
  if (!snapshot) throw new Error('WORKSPACE_NOT_FOUND');
  return snapshot;
}

export async function getMemberProfile(workspaceId: string, requesterId: string, userId: string): Promise<MemberProfile> {
  const snapshot = await requireSnapshot(db, workspaceId);
  if (!snapshot.membersByUserId.has(requesterId) || !snapshot.membersByUserId.has(userId)) throw new Error('MEMBER_NOT_FOUND');
  const user = await db.query.users.findFirst({
    columns: { id: true, displayName: true, avatarUrl: true, bio: true },
    where: eq(users.id, userId),
  });
  if (!user) throw new Error('MEMBER_NOT_FOUND');
  const flag = await db.query.profileFlags.findFirst({
    where: and(eq(profileFlags.workspaceId, workspaceId), eq(profileFlags.userId, userId)),
  });
  let canManageFlag = false;
  try {
    assertFlagAuthority(snapshot, requesterId, userId);
    canManageFlag = true;
  } catch {
    canManageFlag = false;
  }
  return {
    userId,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
    flagged: Boolean(flag),
    canManageFlag,
    ...(canManageFlag && flag ? { appealStatus: flag.appealStatus as ProfileAppealStatus } : {}),
  };
}

export async function getOwnProfile(userId: string): Promise<OwnProfile> {
  const user = await db.query.users.findFirst({
    columns: { displayName: true, avatarUrl: true, bio: true, profileUpdatedAt: true, flagAppealUsedAt: true },
    where: eq(users.id, userId),
  });
  if (!user) throw new Error('USER_NOT_FOUND');
  const memberWorkspaceIds = await workspaceIdsOf(userId);
  const flags = memberWorkspaceIds.length === 0 ? [] : await db.select({
    workspaceId: profileFlags.workspaceId,
    workspaceName: workspaces.name,
    flaggedAt: profileFlags.flaggedAt,
    appealStatus: profileFlags.appealStatus,
  }).from(profileFlags)
    .innerJoin(workspaces, eq(workspaces.id, profileFlags.workspaceId))
    .where(and(eq(profileFlags.userId, userId), inArray(profileFlags.workspaceId, memberWorkspaceIds)))
    .limit(MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1);
  const appealUsed = user.flagAppealUsedAt !== null;
  return {
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
    appealUsed,
    flags: flags.map((flag) => ({
      workspaceId: flag.workspaceId,
      workspaceName: flag.workspaceName,
      appealStatus: flag.appealStatus as ProfileAppealStatus,
      canAppeal: !appealUsed && flag.appealStatus === 'none'
        && user.profileUpdatedAt !== null && user.profileUpdatedAt > flag.flaggedAt,
    })),
  };
}

export async function listProfileFlags(workspaceId: string, actorId: string): Promise<ProfileFlagEntry[]> {
  const snapshot = await requireSnapshot(db, workspaceId);
  if (!canManageFlags(snapshot, actorId)) throw new Error('NOT_AUTHORIZED');
  const memberIds = [...snapshot.membersByUserId.keys()];
  if (memberIds.length === 0) return [];
  const rows = await db.select({
    userId: profileFlags.userId,
    displayName: users.displayName,
    flaggedAt: profileFlags.flaggedAt,
    appealStatus: profileFlags.appealStatus,
    appealRequestedAt: profileFlags.appealRequestedAt,
  }).from(profileFlags)
    .innerJoin(users, eq(users.id, profileFlags.userId))
    .where(and(eq(profileFlags.workspaceId, workspaceId), inArray(profileFlags.userId, memberIds)))
    .limit(MAX_WORKSPACE_MEMBERS + 1);
  return rows.map((row) => ({
    userId: row.userId,
    displayName: row.displayName,
    flaggedAt: row.flaggedAt.toISOString(),
    appealStatus: row.appealStatus as ProfileAppealStatus,
    appealRequestedAt: row.appealRequestedAt?.toISOString() ?? null,
  }));
}

export const MAX_WARNED_USER_IDS = 1000;

/**
 * Users warned in this workspace, including former members whose messages
 * remain, so clients can hide their pictures everywhere in it. `complete` is
 * false when the list was cut; clients then treat unknown non-members as warned.
 */
export async function listWarnedUserIds(workspaceId: string): Promise<{ userIds: string[]; complete: boolean }> {
  const rows = await db.select({ userId: profileFlags.userId }).from(profileFlags)
    .where(eq(profileFlags.workspaceId, workspaceId))
    .orderBy(desc(profileFlags.flaggedAt))
    .limit(MAX_WARNED_USER_IDS + 1);
  return {
    userIds: rows.slice(0, MAX_WARNED_USER_IDS).map((row) => row.userId),
    complete: rows.length <= MAX_WARNED_USER_IDS,
  };
}

export async function flagProfile(workspaceId: string, actorId: string, userId: string) {
  await auditedTransaction(async (tx) => {
    await lockWorkspaceForAuthorization(tx, workspaceId, 'share');
    assertFlagAuthority(await requireSnapshot(tx, workspaceId), actorId, userId);
    await tx.insert(profileFlags).values({ workspaceId, userId, flaggedBy: actorId })
      .onConflictDoNothing();
    return null;
  }, () => ({ actorId, action: 'profile.flag', targetType: 'user', targetId: userId, details: { workspaceId } }));
}

/** Clearing a warning also settles any pending request (it was granted). */
export async function unflagProfile(workspaceId: string, actorId: string, userId: string) {
  await auditedTransaction(async (tx) => {
    await lockWorkspaceForAuthorization(tx, workspaceId, 'share');
    assertFlagAuthority(await requireSnapshot(tx, workspaceId), actorId, userId);
    const removed = await tx.delete(profileFlags)
      .where(and(eq(profileFlags.workspaceId, workspaceId), eq(profileFlags.userId, userId)))
      .returning({ userId: profileFlags.userId });
    if (removed.length !== 1) throw new Error('PROFILE_FLAG_NOT_FOUND');
    return null;
  }, () => ({ actorId, action: 'profile.unflag', targetType: 'user', targetId: userId, details: { workspaceId } }));
}

export async function denyProfileAppeal(workspaceId: string, actorId: string, userId: string) {
  await auditedTransaction(async (tx) => {
    await lockWorkspaceForAuthorization(tx, workspaceId, 'share');
    assertFlagAuthority(await requireSnapshot(tx, workspaceId), actorId, userId);
    const updated = await tx.update(profileFlags).set({ appealStatus: 'denied' })
      .where(and(eq(profileFlags.workspaceId, workspaceId), eq(profileFlags.userId, userId), eq(profileFlags.appealStatus, 'pending')))
      .returning({ userId: profileFlags.userId });
    if (updated.length !== 1) throw new Error('PROFILE_APPEAL_NOT_PENDING');
    return null;
  }, () => ({ actorId, action: 'profile.appeal.deny', targetType: 'user', targetId: userId, details: { workspaceId } }));
}

/**
 * The flagged user's single lifetime request, allowed only after the profile
 * changed since the warning. Returns the managers to notify.
 */
export async function requestProfileAppeal(workspaceId: string, userId: string): Promise<string[]> {
  return auditedTransaction(async (tx) => {
    await lockWorkspaceForAuthorization(tx, workspaceId, 'share');
    const snapshot = await requireSnapshot(tx, workspaceId);
    if (!snapshot.membersByUserId.has(userId)) throw new Error('MEMBER_NOT_FOUND');
    const [user] = await tx.select({ profileUpdatedAt: users.profileUpdatedAt, flagAppealUsedAt: users.flagAppealUsedAt })
      .from(users).where(eq(users.id, userId)).for('update');
    const [flag] = await tx.select().from(profileFlags)
      .where(and(eq(profileFlags.workspaceId, workspaceId), eq(profileFlags.userId, userId))).for('update');
    if (!user || !flag) throw new Error('PROFILE_FLAG_NOT_FOUND');
    if (user.flagAppealUsedAt !== null || flag.appealStatus !== 'none') throw new Error('PROFILE_APPEAL_USED');
    if (!user.profileUpdatedAt || user.profileUpdatedAt <= flag.flaggedAt) throw new Error('PROFILE_APPEAL_NEEDS_CHANGE');
    const now = new Date();
    await tx.update(users).set({ flagAppealUsedAt: now }).where(eq(users.id, userId));
    await tx.update(profileFlags).set({ appealStatus: 'pending', appealRequestedAt: now })
      .where(and(eq(profileFlags.workspaceId, workspaceId), eq(profileFlags.userId, userId)));
    return [...snapshot.membersByUserId.keys()]
      .filter((memberId) => memberId !== userId && canManageFlags(snapshot, memberId))
      .sort();
  }, () => ({ actorId: userId, action: 'profile.appeal.request', targetType: 'user', targetId: userId, details: { workspaceId } }));
}
