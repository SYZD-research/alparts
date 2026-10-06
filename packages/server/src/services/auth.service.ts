import { normalizeEmail } from '../security/email.js';
import { passwordPepper, protectPasswordHash } from '../security/password-pepper.js';
import { createHmac, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { and, eq, gt, lte, ne, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { passkeys, sessions, users } from '../db/schema.js';
import { config } from '../config/index.js';
import { audit, auditedTransaction, type AuditEntry } from '../middleware/audit.js';
import { hashSessionToken } from '../security/session.js';
import { matchesSecret } from '../security/cookies.js';
import { hashPassword, verifyPassword, verifyPasswordForUpgrade, runPublicAuthentication } from '../security/password-work.js';
import { MAX_ACTIVE_SESSIONS_PER_USER } from '../security/limits.js';
import {
  consumeLockedInvitation,
  lockInvitationForConsumption,
  preflightRegistrationInvitation,
} from './invitation.service.js';
import { consumeRegistrationCode, emailVerificationRequired, sendRegistrationCode } from './email-verification.service.js';

const SALT_ROUNDS = 12;
const DUMMY_PASSWORD_HASH = protectPasswordHash('$2b$12$DuhNW97PNP4tI0drdrcUqexxVq.nFCoTXyiFW3mvHNmBgkM7guOJq');

function assertPasswordSupported(password: string): void {
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 12 || bytes > 72) throw new Error('INVALID_PASSWORD_LENGTH');
}

/** The stored form of a new password. Run it before taking any lock. */
export async function hashNewPassword(password: string): Promise<string> {
  assertPasswordSupported(password);
  return hashPassword(password, SALT_ROUNDS);
}

/**
 * First registration step: checks the invitation, then mails a code that
 * proves the address. Returns false when this deployment does not ask for one.
 */
export async function requestRegistrationCode(email: string, inviteToken: string): Promise<boolean> {
  if (!emailVerificationRequired()) return false;
  const normalizedEmail = normalizeEmail(email);
  const bootstrap = matchesSecret(inviteToken, config.auth.registrationInviteSecret);
  await preflightRegistrationInvitation(normalizedEmail, inviteToken, bootstrap);
  await sendRegistrationCode(normalizedEmail);
  return true;
}

export async function register(
  email: string,
  password: string,
  displayName: string,
  inviteToken: string,
  emailCode?: string,
) {
  return runPublicAuthentication(async () => {
    assertPasswordSupported(password);
    const normalizedEmail = normalizeEmail(email);
    const bootstrap = matchesSecret(inviteToken, config.auth.registrationInviteSecret);
    await preflightRegistrationInvitation(normalizedEmail, inviteToken, bootstrap);
    // Only the owner of the address can finish, so a leaked invitation cannot
    // claim someone else's address.
    await consumeRegistrationCode(normalizedEmail, emailCode);
    const passwordHash = await hashPassword(password, SALT_ROUNDS);
    let result;
    try {
      result = await auditedTransaction(
        async (transaction) => {
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

          const [user] = await transaction
            .insert(users)
            .values({
              email: normalizedEmail,
              passwordHash,
              displayName: displayName.trim(),
            })
            .returning();
          const invitation = invitationClaim
            ? await consumeLockedInvitation(transaction, invitationClaim, user.id)
            : null;
          return { user, invitation };
        },
        (committed) => {
          const entries: AuditEntry[] = [
            {
              actorId: committed.user.id,
              action: 'user.register',
              targetType: 'user',
              targetId: committed.user.id,
              details: { bootstrap, workspaceInvitation: Boolean(committed.invitation) },
            },
          ];
          if (committed.invitation) {
            entries.push({
              actorId: committed.user.id,
              action: 'workspace.invitation.use',
              targetType: 'workspace_invitation',
              targetId: committed.invitation.invitationId,
              details: {
                workspaceId: committed.invitation.workspaceId,
                roleId: committed.invitation.roleId,
              },
            });
          }
          return entries;
        },
      );
    } catch (error: any) {
      if (error?.code === '23505') throw new Error('EMAIL_EXISTS');
      throw error;
    }
    return publicUser(result.user);
  });
}

export async function login(email: string, password: string, deviceInfo?: Record<string, unknown>) {
  return runPublicAuthentication(async () => {
    const normalizedEmail = normalizeEmail(email);
    const user = await db.query.users.findFirst({ where: eq(users.email, normalizedEmail) });
    const { valid, upgradedHash } = await verifyPasswordForUpgrade(password, user?.passwordHash || DUMMY_PASSWORD_HASH);
    // A user who turned password login off gets the same answer as a wrong
    // password, so the response never confirms that a password was right.
    if (!user || user.disabledAt || !valid || user.passwordLoginDisabled) {
      await audit({
        action: 'user.login.failed',
        targetType: 'user',
        targetId: user?.id,
        details: {
          accountTag: createHmac('sha256', passwordPepper())
            .update('alparts.login.target.v1\0')
            .update(normalizedEmail)
            .digest('hex'),
        },
      });
      throw new Error('INVALID_CREDENTIALS');
    }

    return establishSession(user, deviceInfo, 'password', undefined, upgradedHash);
  });
}

export async function establishSession(
  user: typeof users.$inferSelect,
  deviceInfo?: Record<string, unknown>,
  method = 'password',
  beforeCreate?: (transaction: any) => Promise<void>,
  upgradedPasswordHash?: string,
) {
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
    if (beforeCreate) await beforeCreate(transaction);
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${user.id}`})::bigint)`);
    const [currentUser] = await transaction.select().from(users).where(eq(users.id, user.id)).for('share');
    if (
      !currentUser
      || currentUser.disabledAt
      || (method === 'password' && (currentUser.passwordHash !== user.passwordHash || currentUser.passwordLoginDisabled))
    ) throw new Error('INVALID_CREDENTIALS');
    await transaction.delete(sessions).where(and(
      eq(sessions.userId, user.id),
      lte(sessions.expiresAt, new Date()),
    ));
    const activeSessions = await transaction.query.sessions.findMany({
      columns: { id: true },
      where: and(eq(sessions.userId, user.id), gt(sessions.expiresAt, new Date())),
      limit: MAX_ACTIVE_SESSIONS_PER_USER + 1,
    });
    if (activeSessions.length >= MAX_ACTIVE_SESSIONS_PER_USER) throw new Error('SESSION_LIMIT_REACHED');
    await transaction.insert(sessions).values({
      id: sessionId,
      userId: user.id,
      tokenHash: hashSessionToken(token),
      deviceInfo: deviceInfo || null,
      authenticationMethod: method,
      expiresAt,
    });
    // A pepper rotation rewraps each credential the first time its password is proven.
    const passwordUpgrade = method === 'password' && upgradedPasswordHash ? { passwordHash: upgradedPasswordHash } : {};
    await transaction.update(users).set({ ...passwordUpgrade, updatedAt: new Date() }).where(eq(users.id, user.id));
    return { sessionId, passwordRewrapped: 'passwordHash' in passwordUpgrade };
  }, (result) => ({
    actorId: user.id,
    action: 'user.login',
    targetType: 'user',
    targetId: user.id,
    ...(result.passwordRewrapped ? { details: { passwordRewrapped: true } } : {}),
  }));

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
    limit: MAX_ACTIVE_SESSIONS_PER_USER + 1,
  });
  if (rows.length > MAX_ACTIVE_SESSIONS_PER_USER) throw new Error('SESSION_INVARIANT_EXCEEDED');
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
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    await transaction.delete(sessions).where(and(
      eq(sessions.userId, userId),
      lte(sessions.expiresAt, new Date()),
    ));
    const removed = await transaction.delete(sessions)
      .where(and(eq(sessions.userId, userId), gt(sessions.expiresAt, new Date())))
      .returning({ id: sessions.id });
    if (removed.length > MAX_ACTIVE_SESSIONS_PER_USER) throw new Error('SESSION_INVARIANT_EXCEEDED');
    return removed.map((session: { id: string }) => session.id);
  }, (removedIds) => ({
    actorId: userId,
    action: 'session.revoke_all',
    targetType: 'user',
    targetId: userId,
    details: { count: removedIds.length },
  }));
}

/**
 * Sets a new password after the session confirmed the user's identity. Every
 * other login ends, and confirmations made with the old password stop working.
 * Returns the ended sessions so their connections can be closed.
 */
export async function changePassword(userId: string, currentSessionId: string, newPassword: string): Promise<string[]> {
  const passwordHash = await hashNewPassword(newPassword);
  return auditedTransaction(async (transaction) => {
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    const [user] = await transaction.select({ disabledAt: users.disabledAt })
      .from(users)
      .where(eq(users.id, userId))
      .for('update');
    if (!user || user.disabledAt) throw new Error('INVALID_CREDENTIALS');
    await transaction.update(users).set({ passwordHash, updatedAt: new Date() }).where(eq(users.id, userId));
    const removed = await transaction.delete(sessions)
      .where(and(eq(sessions.userId, userId), ne(sessions.id, currentSessionId)))
      .returning({ id: sessions.id });
    return removed.map((session: { id: string }) => session.id);
  }, (revoked) => ({
    actorId: userId,
    action: 'user.password.change',
    targetType: 'user',
    targetId: userId,
    details: { revokedSessions: revoked.length },
  }));
}

export async function isPasswordLoginEnabled(userId: string): Promise<boolean> {
  const user = await db.query.users.findFirst({ columns: { passwordLoginDisabled: true }, where: eq(users.id, userId) });
  if (!user) throw new Error('USER_NOT_FOUND');
  return !user.passwordLoginDisabled;
}

/**
 * Turns password login on or off. Turning it off needs a passkey to sign in
 * with, and ends the other logins that were opened with the password.
 * Returns the ended sessions so their connections can be closed.
 */
export async function setPasswordLogin(userId: string, currentSessionId: string, enabled: boolean): Promise<string[]> {
  return auditedTransaction(async (transaction) => {
    // The passkey lock orders this with passkey removal.
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`);
    await transaction.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    const [user] = await transaction.select({ disabledAt: users.disabledAt })
      .from(users)
      .where(eq(users.id, userId))
      .for('update');
    if (!user || user.disabledAt) throw new Error('INVALID_CREDENTIALS');
    if (!enabled) {
      const [key] = await transaction.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.userId, userId)).limit(1);
      if (!key) throw new Error('PASSKEY_REQUIRED');
    }
    await transaction.update(users)
      .set({ passwordLoginDisabled: !enabled, updatedAt: new Date() })
      .where(eq(users.id, userId));
    if (enabled) return [];
    const removed = await transaction.delete(sessions)
      .where(and(
        eq(sessions.userId, userId),
        eq(sessions.authenticationMethod, 'password'),
        ne(sessions.id, currentSessionId),
      ))
      .returning({ id: sessions.id });
    return removed.map((session: { id: string }) => session.id);
  }, (revoked) => ({
    actorId: userId,
    action: enabled ? 'user.password_login.enable' : 'user.password_login.disable',
    targetType: 'user',
    targetId: userId,
    details: { revokedSessions: revoked.length },
  }));
}

export async function getUserById(userId: string) {
  const user = await db.query.users.findFirst({ where: eq(users.id, userId) });
  return user ? publicUser(user) : null;
}

export async function reauthenticate(userId: string, password: string) {
  await verifyCurrentPasswordSnapshot(userId, password);
  const user = await getUserById(userId);
  if (!user) throw new Error('INVALID_CREDENTIALS');
  return user;
}

/**
 * Performs the expensive password KDF before callers acquire an audit, key,
 * or database lock. The returned hash is an opaque revision token; callers
 * must lock and compare it again immediately before the protected mutation.
 */
export async function verifyCurrentPasswordSnapshot(userId: string, password: string): Promise<string> {
  const user = await db.query.users.findFirst({
    columns: { passwordHash: true },
    where: eq(users.id, userId),
  });
  if (!user || !await verifyPassword(password, user.passwordHash)) {
    throw new Error('INVALID_CREDENTIALS');
  }
  return user.passwordHash;
}

/**
 * A short, non-KDF compare under a shared user-row lock closes the password
 * change race without holding a transaction while worker capacity is queued.
 */
export async function assertCurrentPasswordSnapshot(
  store: any,
  userId: string,
  expectedPasswordHash: string,
): Promise<void> {
  const rows = await store.select({ passwordHash: users.passwordHash })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1)
    .for('share') as Array<{ passwordHash: string }>;
  if (!rows[0] || !matchesSecret(rows[0].passwordHash, expectedPasswordHash)) {
    throw new Error('INVALID_CREDENTIALS');
  }
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
