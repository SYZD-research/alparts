import { createHash, timingSafeEqual, createPublicKey, verify } from 'node:crypto';
import { and, asc, eq, gt, isNotNull, isNull, or, sql } from 'drizzle-orm';
import { serializeDeviceDecision, type DirectoryHead, type DirectoryEvent } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  devices,
  historyRecovery,
  historyRecoveryKeys,
  channelKeyEpochRecipients,
  channelKeyEpochs,
  passkeys,
} from '../db/schema.js';
import { config as serverConfig } from '../config/index.js';
import { auditedTransaction } from '../middleware/audit.js';
import { requireApprovedDevice } from './passkey.service.js';
import { lockKeyProtocol } from './key.service.js';
import { appendDirectoryEvent, assertDeviceDecision, directoryHead } from './directory.service.js';
import { abortPendingEpochsForNewDevice } from './device.service.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
} from './authorization.service.js';

async function readRecoveryConfiguration(userId: string) {
  return (
    (await db.query.historyRecovery.findFirst({
      where: eq(historyRecovery.userId, userId),
    })) ?? null
  );
}

export async function recoveryConfiguration(userId: string, sessionId: string) {
  await requireApprovedDevice(db, userId, sessionId);
  const config = await readRecoveryConfiguration(userId);
  return publicConfiguration(config);
}
function publicConfiguration(config: Awaited<ReturnType<typeof readRecoveryConfiguration>>) {
  if (!config) return null;
  const { accessTokenHash, ...result } = config;
  return { ...result, accessConfigured: !!accessTokenHash };
}
function passkeyWrap(config: { encryptedSecret: string }) {
  if (!config.encryptedSecret.startsWith('{')) return undefined;
  let envelope;
  try { envelope = JSON.parse(config.encryptedSecret); }
  catch { throw new Error('INVALID_RECOVERY'); }
  const wrap = envelope.passkeyWrap;
  if (envelope.version !== 2 || !wrap || wrap.version !== 1
    || typeof wrap.credentialId !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/.test(wrap.credentialId)
    || typeof wrap.rpId !== 'string' || !wrap.rpId || wrap.rpId.length > 253
    || typeof wrap.salt !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(wrap.salt)
    || typeof wrap.ciphertext !== 'string' || !/^[A-Za-z0-9+/]{80}$/.test(wrap.ciphertext)
    || typeof envelope.codeSecret !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.codeSecret)) throw new Error('INVALID_RECOVERY');
  return { version: 1, credentialId: wrap.credentialId, rpId: wrap.rpId, salt: wrap.salt, ciphertext: wrap.ciphertext };
}
export async function recoveryMetadata(userId: string, sessionId: string) {
  const live = await db.execute(sql`select d.id from sessions s join devices d on d.id = s.device_id and d.user_id = s.user_id
    where s.id = ${sessionId} and s.user_id = ${userId} and s.expires_at > now() and d.revoked_at is null`);
  if (!live.rows.length) throw new Error('INVALID_RECOVERY');
  const config = await readRecoveryConfiguration(userId);
  return config
    ? {
        generation: config.generation,
        signingKey: config.signingKey,
        accessConfigured: !!config.accessTokenHash,
        passkeyWrap: passkeyWrap(config),
      }
    : null;
}
export async function unlockRecovery(
  userId: string,
  sessionId: string,
  generation: string,
  token: string,
) {
  // A bound, live, non-revoked device plus knowledge of the code is required.
  const result =
    await db.execute(sql`select d.id from sessions s join devices d on d.id = s.device_id and d.user_id = s.user_id
    where s.id = ${sessionId} and s.user_id = ${userId} and s.expires_at > now() and d.revoked_at is null`);
  const config = await readRecoveryConfiguration(userId);
  const digest = createHash('sha256').update(token).digest('hex');
  if (
    !result.rows.length ||
    !config?.accessTokenHash ||
    config.generation !== generation ||
    !/^[a-f0-9]{64}$/.test(config.accessTokenHash) ||
    !timingSafeEqual(Buffer.from(config.accessTokenHash, 'hex'), Buffer.from(digest, 'hex'))
  )
    throw new Error('INVALID_RECOVERY');
  return publicConfiguration(config);
}
export async function enrollRecoveryAccess(
  userId: string,
  sessionId: string,
  generation: string,
  accessTokenHash: string,
) {
  await auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      await requireApprovedDevice(tx, userId, sessionId);
      const updated = await tx
        .update(historyRecovery)
        .set({ accessTokenHash })
        .where(
          and(
            eq(historyRecovery.userId, userId),
            eq(historyRecovery.generation, generation),
            isNull(historyRecovery.accessTokenHash),
          ),
        )
        .returning({ userId: historyRecovery.userId });
      if (updated.length !== 1) throw new Error('INVALID_RECOVERY');
    },
    () => ({
      actorId: userId,
      action: 'recovery.access.enroll',
      targetType: 'user',
      targetId: userId,
    }),
  );
}

export async function configureRecovery(
  userId: string,
  sessionId: string,
  input: {
    generation: string;
    signingKey: string;
    encryptedSecret: string;
    accessTokenHash: string;
    head: DirectoryHead;
    signature: string;
  },
) {
  let parsed;
  try {
    parsed = JSON.parse(input.signingKey);
  } catch {
    throw new Error('INVALID_RECOVERY');
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    parsed.kty !== 'EC' ||
    parsed.crv !== 'P-256' ||
    parsed.d ||
    Object.keys(parsed).some((k) => !['kty', 'crv', 'x', 'y'].includes(k))
  )
    throw new Error('INVALID_RECOVERY');
  let key;
  try {
    key = createPublicKey({ key: parsed, format: 'jwk' });
  } catch {
    throw new Error('INVALID_RECOVERY');
  }
  if (key.asymmetricKeyType !== 'ec') throw new Error('INVALID_RECOVERY');
  await auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      const actor = await requireApprovedDevice(tx, userId, sessionId);
      const wrap = passkeyWrap(input);
      if (wrap && (wrap.rpId !== serverConfig.webauthn.rpId || !await tx.query.passkeys.findFirst({
        where: and(eq(passkeys.id, wrap.credentialId), eq(passkeys.userId, userId)),
      }))) throw new Error('INVALID_RECOVERY');
      const event: DirectoryEvent = {
        kind: 'recovery-config',
        deviceId: input.generation,
        identityKey: input.signingKey,
        actorDeviceId: actor.id,
        signature: input.signature,
      };
      await assertDeviceDecision(tx, userId, actor.id, input.head, event);
      // Replacing a code requires explicit disable first so a retry cannot destroy
      // the only usable archive or silently replace a recovery recipient.
      if (
        await tx.query.historyRecovery.findFirst({
          where: eq(historyRecovery.userId, userId),
        })
      )
        throw new Error('RECOVERY_ALREADY_CONFIGURED');
      await tx.insert(historyRecovery).values({
        userId,
        generation: input.generation,
        signingKey: input.signingKey,
        encryptedSecret: input.encryptedSecret,
        accessTokenHash: input.accessTokenHash,
      });
      await appendDirectoryEvent(tx, userId, event);
    },
    () => ({
      actorId: userId,
      action: 'recovery.configure',
      targetType: 'user',
      targetId: userId,
    }),
  );
}

export async function restoreDevice(
  userId: string,
  sessionId: string,
  input: { generation: string; head: DirectoryHead; signature: string },
) {
  return auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      const [session] = await tx
        .execute(
          sql`select device_id from sessions where id = ${sessionId} and user_id = ${userId} and expires_at > now() for share`,
        )
        .then((r: any) => r.rows);
      if (!session?.device_id) throw new Error('INVALID_RECOVERY');
      const [device] = await tx
        .select()
        .from(devices)
        .where(
          and(
            eq(devices.id, session.device_id),
            eq(devices.userId, userId),
            isNull(devices.revokedAt),
          ),
        )
        .for('update');
      // Approval is one-way. A replay against an approved device must not
      // append further directory events.
      if (device?.approvedAt) return { dirtyWorkspaceIds: [], alreadyApproved: true };
      const recovery = await tx.query.historyRecovery.findFirst({
        where: and(
          eq(historyRecovery.userId, userId),
          eq(historyRecovery.generation, input.generation),
        ),
      });
      const head = await directoryHead(tx, userId);
      if (
        !device ||
        !recovery ||
        head.hash !== input.head.hash ||
        head.sequence !== input.head.sequence ||
        input.head.userId !== userId
      )
        throw new Error('INVALID_RECOVERY');
      const event: DirectoryEvent = {
        kind: 'recovery',
        deviceId: device.id,
        identityKey: device.identityKey,
        actorDeviceId: input.generation,
        signature: input.signature,
      };
      if (
        !verify(
          'sha256',
          Buffer.from(serializeDeviceDecision(head, event)),
          {
            key: createPublicKey({
              key: JSON.parse(recovery.signingKey),
              format: 'jwk',
            }),
            dsaEncoding: 'ieee-p1363',
          },
          Buffer.from(input.signature, 'base64'),
        )
      )
        throw new Error('INVALID_RECOVERY');
      await tx.update(devices).set({ approvedAt: new Date() }).where(eq(devices.id, device.id));
      await appendDirectoryEvent(tx, userId, event);
      return {
        dirtyWorkspaceIds: await abortPendingEpochsForNewDevice(tx, userId),
        alreadyApproved: false,
      };
    },
    (result) => ({
      actorId: userId,
      action: 'recovery.device',
      targetType: 'user',
      targetId: userId,
      ...(result.alreadyApproved ? { details: { alreadyApproved: true } } : {}),
    }),
  );
}

export interface HistoryKeyBackup {
  generation: string;
  channelId: string;
  version: number;
  keyCommitment: string;
  ciphertext: string;
}
export async function backupHistoryKeys(
  userId: string,
  sessionId: string,
  inputs: HistoryKeyBackup[],
) {
  if (!inputs.length || inputs.length > 64) throw new Error('RECOVERY_LIMIT');
  await auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      await requireApprovedDevice(tx, userId, sessionId);
      for (const input of inputs) {
        const config = await tx.query.historyRecovery.findFirst({
          where: and(
            eq(historyRecovery.userId, userId),
            eq(historyRecovery.generation, input.generation),
          ),
        });
        const auth = await getChannelAuthorizationFromStore(tx, userId, input.channelId);
        if (!config || !isVisibleChannelAuthorization(auth)) throw new Error('INVALID_RECOVERY');
        const [accepted] = await tx
          .select({ commitment: channelKeyEpochs.keyCommitment })
          .from(channelKeyEpochRecipients)
          .innerJoin(
            channelKeyEpochs,
            and(
              eq(channelKeyEpochs.channelId, channelKeyEpochRecipients.channelId),
              eq(channelKeyEpochs.version, channelKeyEpochRecipients.version),
            ),
          )
          .where(
            and(
              eq(channelKeyEpochRecipients.channelId, input.channelId),
              eq(channelKeyEpochRecipients.version, input.version),
              eq(channelKeyEpochRecipients.userId, userId),
              isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
            ),
          );
        if (!accepted || accepted.commitment !== input.keyCommitment)
          throw new Error('INVALID_RECOVERY');
        const existing = await tx.query.historyRecoveryKeys.findFirst({
          where: and(
            eq(historyRecoveryKeys.userId, userId),
            eq(historyRecoveryKeys.generation, input.generation),
            eq(historyRecoveryKeys.channelId, input.channelId),
            eq(historyRecoveryKeys.version, input.version),
          ),
        });
        if (existing) continue;
        const [count] = await tx
          .select({ value: sql<number>`count(*)::int` })
          .from(historyRecoveryKeys)
          .where(eq(historyRecoveryKeys.userId, userId));
        if (count.value >= 100_000) throw new Error('RECOVERY_LIMIT');
        await tx
          .insert(historyRecoveryKeys)
          .values({ ...input, userId })
          .onConflictDoNothing();
      }
    },
    () => ({
      actorId: userId,
      action: 'recovery.key.backup',
      targetType: 'user',
      targetId: userId,
      details: { count: inputs.length },
    }),
  );
}

export async function recoveryKeyPage(
  userId: string,
  sessionId: string,
  cursor?: { channelId: string; version: number },
) {
  const config = await recoveryConfiguration(userId, sessionId);
  if (!config) return { keys: [], cursor: null };
  const rows = await db
    .select()
    .from(historyRecoveryKeys)
    .where(
      and(
        eq(historyRecoveryKeys.userId, userId),
        eq(historyRecoveryKeys.generation, config.generation),
        cursor
          ? or(
              gt(historyRecoveryKeys.channelId, cursor.channelId),
              and(
                eq(historyRecoveryKeys.channelId, cursor.channelId),
                gt(historyRecoveryKeys.version, cursor.version),
              ),
            )
          : undefined,
      ),
    )
    .orderBy(asc(historyRecoveryKeys.channelId), asc(historyRecoveryKeys.version))
    .limit(64);
  const keys = [];
  for (const row of rows)
    if (
      isVisibleChannelAuthorization(
        await getChannelAuthorizationFromStore(db, userId, row.channelId),
      )
    )
      keys.push(row);
  const last = rows.at(-1);
  return {
    keys,
    cursor:
      rows.length === 64 && last ? { channelId: last.channelId, version: last.version } : null,
  };
}

export async function historyBackupCandidates(
  userId: string,
  sessionId: string,
  cursor?: { channelId: string; version: number },
) {
  await requireApprovedDevice(db, userId, sessionId);
  const rows = await db
    .selectDistinct({
      channelId: channelKeyEpochRecipients.channelId,
      version: channelKeyEpochRecipients.version,
    })
    .from(channelKeyEpochRecipients)
    .where(
      and(
        eq(channelKeyEpochRecipients.userId, userId),
        isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
        cursor
          ? or(
              gt(channelKeyEpochRecipients.channelId, cursor.channelId),
              and(
                eq(channelKeyEpochRecipients.channelId, cursor.channelId),
                gt(channelKeyEpochRecipients.version, cursor.version),
              ),
            )
          : undefined,
      ),
    )
    .orderBy(asc(channelKeyEpochRecipients.channelId), asc(channelKeyEpochRecipients.version))
    .limit(64);
  const candidates = [];
  for (const row of rows)
    if (
      isVisibleChannelAuthorization(
        await getChannelAuthorizationFromStore(db, userId, row.channelId),
      )
    )
      candidates.push(row);
  return { candidates, cursor: rows.length === 64 ? rows.at(-1)! : null };
}

export async function disableRecovery(
  userId: string,
  sessionId: string,
  input: { head: DirectoryHead; signature: string },
) {
  await auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      const actor = await requireApprovedDevice(tx, userId, sessionId);
      const config = await tx.query.historyRecovery.findFirst({
        where: eq(historyRecovery.userId, userId),
      });
      if (!config) throw new Error('INVALID_RECOVERY');
      const event: DirectoryEvent = {
        kind: 'recovery-disable',
        deviceId: config.generation,
        identityKey: config.signingKey,
        actorDeviceId: actor.id,
        signature: input.signature,
      };
      await assertDeviceDecision(tx, userId, actor.id, input.head, event);
      await tx.delete(historyRecoveryKeys).where(eq(historyRecoveryKeys.userId, userId));
      await tx.delete(historyRecovery).where(eq(historyRecovery.userId, userId));
      await appendDirectoryEvent(tx, userId, event);
    },
    () => ({
      actorId: userId,
      action: 'recovery.disable',
      targetType: 'user',
      targetId: userId,
    }),
  );
}
