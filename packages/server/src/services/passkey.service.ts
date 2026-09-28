import { randomBytes, randomUUID } from 'node:crypto';
import { and, eq, gt, isNotNull, isNull, lte, sql } from 'drizzle-orm';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type AuthenticatorTransport,
} from '@simplewebauthn/server';
import { db } from '../db/index.js';
import {
  authenticationChallenges,
  devices,
  passkeys,
  sessions,
  stepUpGrants,
  users,
} from '../db/schema.js';
import { config } from '../config/index.js';
import { auditedTransaction } from '../middleware/audit.js';
import { hashSessionToken } from '../security/session.js';
import {
  establishSession,
  verifyCurrentPasswordSnapshot,
  assertCurrentPasswordSnapshot,
} from './auth.service.js';

const MAX_PASSKEYS = 8;
const challengeTtl = 5 * 60_000;

export async function listPasskeys(userId: string) {
  const rows = await db
    .select({
      id: passkeys.id,
      name: passkeys.name,
      createdAt: passkeys.createdAt,
    })
    .from(passkeys)
    .where(eq(passkeys.userId, userId))
    .limit(MAX_PASSKEYS + 1);
  if (rows.length > MAX_PASSKEYS) throw new Error('AUTHENTICATION_LIMIT');
  return rows;
}

async function issueChallenge(
  challenge: string,
  purpose: string,
  userId: string | null,
  sessionId: string | null,
) {
  const id = randomUUID();
  await auditedTransaction(
    async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(1095520331)`);
      await tx
        .delete(authenticationChallenges)
        .where(lte(authenticationChallenges.expiresAt, new Date()));
      const count = await tx
        .select({ id: authenticationChallenges.id })
        .from(authenticationChallenges)
        .limit(4096);
      if (count.length >= 4096) throw new Error('AUTHENTICATION_LIMIT');
      if (sessionId) {
        await requireLiveSession(tx, userId!, sessionId);
        const pending = await tx
          .select({ id: authenticationChallenges.id })
          .from(authenticationChallenges)
          .where(eq(authenticationChallenges.sessionId, sessionId))
          .limit(8);
        if (pending.length >= 8) throw new Error('AUTHENTICATION_LIMIT');
      }
      await tx.insert(authenticationChallenges).values({
        id,
        challenge,
        purpose,
        userId,
        sessionId,
        expiresAt: new Date(Date.now() + challengeTtl),
      });
    },
    () => ({
      actorId: userId ?? undefined,
      action: 'authentication.challenge',
      targetType: 'user',
      targetId: userId ?? undefined,
    }),
  );
  return id;
}

// Consume before verification, including failed assertions. A challenge cannot
// be retried, reused in another session, or survive a server restart indefinitely.
async function takeChallenge(id: string, purpose: string, sessionId: string | null) {
  return auditedTransaction(
    async (tx) => {
      const [row] = await tx
        .delete(authenticationChallenges)
        .where(
          and(
            eq(authenticationChallenges.id, id),
            eq(authenticationChallenges.purpose, purpose),
            sessionId
              ? eq(authenticationChallenges.sessionId, sessionId)
              : isNull(authenticationChallenges.sessionId),
            gt(authenticationChallenges.expiresAt, new Date()),
          ),
        )
        .returning();
      if (!row) throw new Error('AUTHENTICATION_FAILED');
      return row;
    },
    () => ({ action: 'authentication.challenge.consume' }),
  );
}

async function requireLiveSession(tx: any, userId: string, sessionId: string) {
  const [session] = await tx
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.id, sessionId),
        eq(sessions.userId, userId),
        gt(sessions.expiresAt, new Date()),
      ),
    )
    .for('share');
  if (!session) throw new Error('AUTHENTICATION_FAILED');
  return session;
}

export async function requireApprovedDevice(tx: any, userId: string, sessionId: string) {
  const session = await requireLiveSession(tx, userId, sessionId);
  const [device] = await tx
    .select()
    .from(devices)
    .where(
      and(
        eq(devices.id, session.deviceId),
        eq(devices.userId, userId),
        isNull(devices.revokedAt),
        isNotNull(devices.approvedAt),
      ),
    )
    .for('share');
  if (!device) throw new Error('DEVICE_APPROVAL_REQUIRED');
  return device;
}

export async function registrationOptions(userId: string, sessionId: string) {
  await requireApprovedDevice(db, userId, sessionId);
  const user = await db.query.users.findFirst({ where: eq(users.id, userId) });
  if (!user) throw new Error('AUTHENTICATION_FAILED');
  const keys = await listPasskeys(userId);
  if (keys.length >= MAX_PASSKEYS) throw new Error('AUTHENTICATION_LIMIT');
  const options = await generateRegistrationOptions({
    rpID: config.webauthn.rpId,
    rpName: 'alparts',
    userName: user.email,
    userID: new TextEncoder().encode(user.id),
    userDisplayName: user.displayName,
    attestationType: 'none',
    supportedAlgorithmIDs: [-7, -257, -8],
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    excludeCredentials: keys.map(({ id }) => ({ id })),
  });
  return {
    id: await issueChallenge(options.challenge, 'register', userId, sessionId),
    options,
  };
}

export async function finishRegistration(
  userId: string,
  sessionId: string,
  id: string,
  name: string,
  response: RegistrationResponseJSON,
) {
  const challenge = await takeChallenge(id, 'register', sessionId);
  if (challenge.userId !== userId) throw new Error('AUTHENTICATION_FAILED');
  const result = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.webauthn.origins,
    expectedRPID: config.webauthn.rpId,
    requireUserVerification: true,
  }).catch(() => {
    throw new Error('AUTHENTICATION_FAILED');
  });
  if (!result.verified) throw new Error('AUTHENTICATION_FAILED');
  const credential = result.registrationInfo.credential;
  await auditedTransaction(
    async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`,
      );
      await requireApprovedDevice(tx, userId, sessionId);
      const rows = await tx
        .select({ id: passkeys.id })
        .from(passkeys)
        .where(eq(passkeys.userId, userId))
        .limit(MAX_PASSKEYS);
      if (rows.length >= MAX_PASSKEYS) throw new Error('AUTHENTICATION_LIMIT');
      await tx.insert(passkeys).values({
        id: credential.id,
        userId,
        name,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        transports: credential.transports ?? [],
      });
    },
    () => ({
      actorId: userId,
      action: 'passkey.register',
      targetType: 'user',
      targetId: userId,
    }),
  );
}

export async function authenticationOptions(
  purpose: string,
  userId: string | null,
  sessionId: string | null,
) {
  if (userId && sessionId) await requireApprovedDevice(db, userId, sessionId);
  const keys = userId ? await listPasskeys(userId) : [];
  const options = await generateAuthenticationOptions({
    rpID: config.webauthn.rpId,
    userVerification: 'required',
    ...(userId ? { allowCredentials: keys.map(({ id }) => ({ id })) } : {}),
  });
  return {
    id: await issueChallenge(options.challenge, purpose, userId, sessionId),
    options,
    passwordAllowed: !!userId && keys.length === 0,
  };
}

async function verifyAssertion(
  challenge: typeof authenticationChallenges.$inferSelect,
  response: AuthenticationResponseJSON,
) {
  const credential = await db.query.passkeys.findFirst({
    where: eq(passkeys.id, response.id),
  });
  if (!credential || (challenge.userId && credential.userId !== challenge.userId))
    throw new Error('AUTHENTICATION_FAILED');
  if (
    response.response.userHandle &&
    Buffer.from(response.response.userHandle, 'base64url').toString('utf8') !== credential.userId
  )
    throw new Error('AUTHENTICATION_FAILED');
  const result = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.webauthn.origins,
    expectedRPID: config.webauthn.rpId,
    requireUserVerification: true,
    credential: {
      id: credential.id,
      publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')),
      counter: credential.counter,
      transports: credential.transports as AuthenticatorTransport[],
    },
  }).catch(() => {
    throw new Error('AUTHENTICATION_FAILED');
  });
  if (!result.verified || !result.authenticationInfo.userVerified)
    throw new Error('AUTHENTICATION_FAILED');
  return { credential, newCounter: result.authenticationInfo.newCounter };
}

async function advanceCounter(tx: any, result: Awaited<ReturnType<typeof verifyAssertion>>) {
  const updated = await tx
    .update(passkeys)
    .set({ counter: result.newCounter })
    .where(
      and(eq(passkeys.id, result.credential.id), eq(passkeys.counter, result.credential.counter)),
    )
    .returning({ id: passkeys.id });
  if (updated.length !== 1) throw new Error('AUTHENTICATION_FAILED');
}

export async function passkeyLogin(id: string, response: AuthenticationResponseJSON) {
  const challenge = await takeChallenge(id, 'login', null);
  const result = await verifyAssertion(challenge, response);
  const user = await db.query.users.findFirst({
    where: eq(users.id, result.credential.userId),
  });
  if (!user) throw new Error('AUTHENTICATION_FAILED');
  return establishSession(user, undefined, 'passkey', (tx) => advanceCounter(tx, result));
}

export async function finishStepUp(
  userId: string,
  sessionId: string,
  id: string,
  purpose: string,
  response?: AuthenticationResponseJSON,
  password?: string,
) {
  const challenge = await takeChallenge(id, purpose, sessionId);
  if (challenge.userId !== userId) throw new Error('AUTHENTICATION_FAILED');
  const assertion = response ? await verifyAssertion(challenge, response) : null;
  const passwordHash =
    !assertion && password ? await verifyCurrentPasswordSnapshot(userId, password) : null;
  if (!assertion && !passwordHash) throw new Error('AUTHENTICATION_FAILED');
  const token = randomBytes(32).toString('base64url');
  await auditedTransaction(
    async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`,
      );
      await requireApprovedDevice(tx, userId, sessionId);
      if (assertion) await advanceCounter(tx, assertion);
      else {
        const [key] = await tx
          .select({ id: passkeys.id })
          .from(passkeys)
          .where(eq(passkeys.userId, userId))
          .limit(1);
        if (key) throw new Error('PASSKEY_REQUIRED');
        await assertCurrentPasswordSnapshot(tx, userId, passwordHash!);
      }
      await tx
        .delete(stepUpGrants)
        .where(and(eq(stepUpGrants.sessionId, sessionId), lte(stepUpGrants.expiresAt, new Date())));
      const grants = await tx
        .select({ tokenHash: stepUpGrants.tokenHash })
        .from(stepUpGrants)
        .where(eq(stepUpGrants.sessionId, sessionId))
        .limit(8);
      if (grants.length >= 8) throw new Error('AUTHENTICATION_LIMIT');
      await tx.insert(stepUpGrants).values({
        tokenHash: hashSessionToken(token),
        sessionId,
        purpose,
        authentication: assertion
          ? {
              method: 'passkey',
              credentialId: assertion.credential.id,
              publicKey: assertion.credential.publicKey,
            }
          : { method: 'password', passwordHash },
        expiresAt: new Date(Date.now() + 120_000),
      });
    },
    () => ({
      actorId: userId,
      action: 'authentication.step_up',
      targetType: 'user',
      targetId: userId,
      details: { method: assertion ? 'passkey' : 'password' },
    }),
  );
  return { token };
}

export async function consumeStepUp(sessionId: string, purpose: string, token: string) {
  return auditedTransaction(
    async (tx) => {
      const removed = await tx
        .delete(stepUpGrants)
        .where(
          and(
            eq(stepUpGrants.tokenHash, hashSessionToken(token)),
            eq(stepUpGrants.sessionId, sessionId),
            eq(stepUpGrants.purpose, purpose),
            gt(stepUpGrants.expiresAt, new Date()),
          ),
        )
        .returning();
      const grant = removed[0];
      if (!grant) return null;
      const [session] = await tx.select().from(sessions).where(eq(sessions.id, sessionId));
      if (!session) return null;
      try {
        await validateStepUpAuthentication(tx, session.userId, sessionId, grant.authentication);
      } catch (error) {
        if (
          error instanceof Error &&
          [
            'AUTHENTICATION_FAILED',
            'INVALID_CREDENTIALS',
            'PASSKEY_REQUIRED',
            'DEVICE_APPROVAL_REQUIRED',
          ].includes(error.message)
        )
          return null;
        throw error;
      }
      const proof = Object.freeze({
        sessionId,
        userId: session.userId,
        purpose,
        expiresAt: grant.expiresAt.getTime(),
      });
      stepUpProofs.set(proof, grant.authentication);
      return proof;
    },
    () => ({ action: 'authentication.step_up.consume' }),
  );
}

export async function deletePasskey(userId: string, id: string) {
  await auditedTransaction(
    async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`,
      );
      const keys = await tx
        .select({ id: passkeys.id })
        .from(passkeys)
        .where(eq(passkeys.userId, userId))
        .limit(MAX_PASSKEYS + 1);
      if (keys.length <= 1) throw new Error('LAST_PASSKEY');
      await tx.delete(passkeys).where(and(eq(passkeys.id, id), eq(passkeys.userId, userId)));
    },
    () => ({
      actorId: userId,
      action: 'passkey.delete',
      targetType: 'user',
      targetId: userId,
    }),
  );
}

// Receipts are server-created capabilities; JSON/body objects cannot manufacture one.
export interface StepUpProof {
  readonly sessionId: string;
  readonly userId: string;
  readonly purpose: string;
  readonly expiresAt: number;
}
const stepUpProofs = new WeakMap<StepUpProof, unknown>();
async function validateStepUpAuthentication(
  tx: any,
  userId: string,
  sessionId: string,
  authentication: any,
) {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`);
  const device = await requireApprovedDevice(tx, userId, sessionId);
  if (authentication?.method === 'passkey') {
    const [key] = await tx
      .select()
      .from(passkeys)
      .where(
        and(
          eq(passkeys.id, authentication.credentialId),
          eq(passkeys.userId, userId),
          eq(passkeys.publicKey, authentication.publicKey),
        ),
      )
      .for('share');
    if (!key) throw new Error('AUTHENTICATION_FAILED');
  } else if (
    authentication?.method === 'password' &&
    typeof authentication.passwordHash === 'string'
  ) {
    const [key] = await tx
      .select({ id: passkeys.id })
      .from(passkeys)
      .where(eq(passkeys.userId, userId))
      .limit(1);
    if (key) throw new Error('PASSKEY_REQUIRED');
    await assertCurrentPasswordSnapshot(tx, userId, authentication.passwordHash);
  } else throw new Error('AUTHENTICATION_FAILED');
  return device;
}
export async function assertFreshStartStepUp(
  tx: any,
  proof: StepUpProof | undefined,
  userId: string,
  deviceId: string,
  purpose: string,
) {
  if (
    !proof ||
    !stepUpProofs.has(proof) ||
    proof.userId !== userId ||
    proof.purpose !== purpose ||
    proof.expiresAt <= Date.now()
  )
    throw new Error('AUTHENTICATION_FAILED');
  const authentication = stepUpProofs.get(proof);
  stepUpProofs.delete(proof);
  const device = await validateStepUpAuthentication(tx, userId, proof.sessionId, authentication);
  if (device.id !== deviceId) throw new Error('AUTHENTICATION_FAILED');
}
