import { and, eq, inArray, isNull, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import {
  channelKeyEpochs,
  channels,
  devices,
  sessions,
  workspaceMembers,
  workspaces,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import {
  canonicalDeviceIdentityKey,
  verifyDeviceChallengeSignature,
} from '../security/message.js';
import { deviceChallenges } from '../security/device-challenge.js';
import { MAX_ACTIVE_DEVICES_PER_USER } from '../security/limits.js';
import { assertCurrentPassword } from './auth.service.js';
import { lockKeyProtocol } from './key.service.js';
import {
  abortPendingChannelKeyEpochs,
  requireChannelKeyRotation,
} from './key-epoch-state.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockChannelAuthorization,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';

const ACTIVITY_WRITE_INTERVAL_MS = 5 * 60 * 1000;
const MAX_IDENTITY_MATCH_SCAN = 1_024;
const recentActivityWrites = new Map<string, number>();

export function issueDeviceChallenge(userId: string, sessionId: string): string {
  return deviceChallenges.issue(userId, sessionId);
}

function assertDeviceProof(
  userId: string,
  sessionId: string,
  identityKey: string,
  challenge: string,
  proof: string,
): void {
  if (
    !deviceChallenges.consume(userId, sessionId, challenge)
    || !verifyDeviceChallengeSignature(identityKey, userId, challenge, proof)
  ) throw new Error('INVALID_DEVICE_PROOF');
}

export async function registerDevice(
  userId: string,
  sessionId: string,
  name: string,
  suppliedIdentityKey: string,
  challenge: string,
  proof: string,
  currentPassword?: string,
) {
  const identityKey = canonicalDeviceIdentityKey(suppliedIdentityKey);
  assertDeviceProof(userId, sessionId, identityKey, challenge, proof);
  const result = await auditedTransaction<{
    device: typeof devices.$inferSelect;
    created: boolean;
    abortedChannelIds: string[];
  }>(async (tx) => {
    await lockKeyProtocol(tx);
    // The client may retry registration after losing a response, and two tabs
    // can race during first-use initialization. Serialize by user so one
    // cryptographic identity is represented by at most one active device.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`device-register:${userId}`})::bigint)`);
    const candidates = await tx.select()
      .from(devices)
      .where(eq(devices.userId, userId))
      .limit(MAX_IDENTITY_MATCH_SCAN + 1)
      .for('update') as Array<typeof devices.$inferSelect>;
    const matches = candidates.filter((device) => {
      if (device.identityKey === suppliedIdentityKey || device.identityKey === identityKey) return true;
      try {
        return canonicalDeviceIdentityKey(device.identityKey) === identityKey;
      } catch {
        return false;
      }
    });
    if (candidates.length > MAX_IDENTITY_MATCH_SCAN && matches.length === 0) {
      throw new Error('DEVICE_IDENTITY_REVIEW_REQUIRED');
    }

    // A revoked cryptographic identity must never reappear under a new row.
    // The browser generates a fresh identity before registering again.
    if (matches.some((device) => device.revokedAt !== null)) throw new Error('IDENTITY_REVOKED');
    const active = matches[0];
    if (active) {
      if (active.identityKey !== identityKey) {
        await tx.update(devices).set({ identityKey }).where(eq(devices.id, active.id));
        active.identityKey = identityKey;
      }
      const bound = await tx.update(sessions)
        .set({ deviceId: active.id })
        .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId)))
        .returning({ id: sessions.id }) as Array<{ id: string }>;
      if (bound.length !== 1) throw new Error('SESSION_NOT_FOUND');
      return { device: active, created: false, abortedChannelIds: [] };
    }

    if (!currentPassword) throw new Error('DEVICE_STEP_UP_REQUIRED');
    await assertCurrentPassword(tx, userId, currentPassword);
    const activeDevices = await tx.select({ id: devices.id })
      .from(devices)
      .where(and(eq(devices.userId, userId), isNull(devices.revokedAt)))
      .limit(MAX_ACTIVE_DEVICES_PER_USER + 1) as Array<{ id: string }>;
    if (activeDevices.length >= MAX_ACTIVE_DEVICES_PER_USER) throw new Error('DEVICE_LIMIT_REACHED');

    const inserted = await tx.insert(devices).values({ userId, name, identityKey }).returning() as Array<typeof devices.$inferSelect>;
    const bound = await tx.update(sessions)
      .set({ deviceId: inserted[0].id })
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId)))
      .returning({ id: sessions.id }) as Array<{ id: string }>;
    if (bound.length !== 1) throw new Error('SESSION_NOT_FOUND');
    const abortedChannelIds = await abortPendingEpochsForNewDevice(tx, userId);
    return { device: inserted[0], created: true, abortedChannelIds };
  }, ({ device, created }) => ({
    actorId: userId,
    action: created ? 'device.register' : 'device.bind',
    targetType: 'device',
    targetId: device.id,
    details: created ? { name } : { reason: 'registration-retry' },
  }));
  return {
    device: formatDevice(result.device),
    created: result.created,
    abortedChannelIds: result.abortedChannelIds,
  };
}

export async function bindDevice(
  deviceId: string,
  userId: string,
  sessionId: string,
  challenge: string,
  proof: string,
) {
  const candidate = await db.query.devices.findFirst({
    where: and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)),
  });
  if (!candidate) throw new Error('DEVICE_NOT_FOUND');
  assertDeviceProof(userId, sessionId, candidate.identityKey, challenge, proof);
  const device = await auditedTransaction<typeof devices.$inferSelect>(async (transaction) => {
    const [activeDevice] = await transaction.select()
      .from(devices)
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
      .for('share') as Array<typeof devices.$inferSelect>;
    if (!activeDevice) throw new Error('DEVICE_NOT_FOUND');
    const bound = await transaction.update(sessions)
      .set({ deviceId })
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId)))
      .returning({ id: sessions.id }) as Array<{ id: string }>;
    if (bound.length !== 1) throw new Error('SESSION_NOT_FOUND');
    return activeDevice;
  }, () => ({ actorId: userId, action: 'device.bind', targetType: 'device', targetId: deviceId }));
  return formatDevice(device);
}

export async function getUserDevices(userId: string) {
  const rows = await db.query.devices.findMany({
    where: and(eq(devices.userId, userId), isNull(devices.revokedAt)),
  });
  return rows.map(formatDevice);
}

async function abortPendingEpochsForNewDevice(store: any, userId: string): Promise<string[]> {
  const membershipRows = await store.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
  }) as Array<{ workspaceId: string }>;
  const workspaceIds = [...new Set(membershipRows.map((row) => row.workspaceId))].sort();
  for (const workspaceId of workspaceIds) {
    await lockWorkspaceForAuthorization(store, workspaceId, 'update');
  }
  if (workspaceIds.length === 0) return [];

  const workspaceChannels = await store.query.channels.findMany({
    where: inArray(channels.workspaceId, workspaceIds),
  }) as Array<typeof channels.$inferSelect>;
  if (workspaceChannels.length === 0) return [];
  const pendingRows = await store.query.channelKeyEpochs.findMany({
    columns: { channelId: true },
    where: and(
      inArray(channelKeyEpochs.channelId, workspaceChannels.map((channel) => channel.id)),
      eq(channelKeyEpochs.status, 'pending'),
    ),
  }) as Array<{ channelId: string }>;
  const pendingIds = new Set(pendingRows.map((row) => row.channelId));
  const pendingChannels = workspaceChannels
    .filter((channel) => pendingIds.has(channel.id))
    .sort((left, right) => left.id.localeCompare(right.id));
  for (const channel of pendingChannels) await lockChannelAuthorization(store, channel.id);

  const visiblePendingChannelIds: string[] = [];
  for (const channel of pendingChannels) {
    const authorization = await getChannelAuthorizationFromStore(store, userId, channel);
    if (isVisibleChannelAuthorization(authorization)) visiblePendingChannelIds.push(channel.id);
  }
  // Device gain changes the provisional recipient set, but standard Secure
  // semantics permit backfilling this device into the current active epoch.
  return abortPendingChannelKeyEpochs(store, visiblePendingChannelIds);
}

export async function revokeDevice(
  deviceId: string,
  userId: string,
): Promise<{ sessionIds: string[]; affectedChannelIds: string[] }> {
  const result = await auditedTransaction<{
    boundSessionIds: string[];
    changed: boolean;
    affectedChannelIds: string[];
  }>(async (tx) => {
    await lockKeyProtocol(tx);
    // Follow the distribution lock order: workspace(s), channel(s), device.
    // The unlocked discovery is repeated after all locks and is only used to
    // determine the finite lock set.
    const discovered = await findCurrentKeyChannels(tx, deviceId);
    const workspaceIds = [...new Set(discovered.map((row) => row.workspaceId))].sort();
    for (const workspaceId of workspaceIds) {
      await tx.execute(sql`select id from ${workspaces} where ${workspaces.id} = ${workspaceId} for update`);
    }
    const discoveredChannelIds = [...new Set(discovered.map((row) => row.channelId))].sort();
    for (const channelId of discoveredChannelIds) {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${channelId})::bigint)`);
    }
    const [device] = await tx.select()
      .from(devices)
      .where(eq(devices.id, deviceId))
      .for('update');
    if (!device) throw new Error('DEVICE_NOT_FOUND');
    if (device.userId !== userId) throw new Error('NOT_AUTHORIZED');
    if (device.revokedAt) return { boundSessionIds: [], changed: false, affectedChannelIds: [] };

    const boundSessions = await tx.query.sessions.findMany({
      columns: { id: true },
      where: and(eq(sessions.deviceId, deviceId), eq(sessions.userId, userId)),
    }) as Array<{ id: string }>;
    const currentKeyChannels = await findCurrentKeyChannels(tx, deviceId);
    const affectedChannelIds: string[] = [];
    for (const candidateChannel of currentKeyChannels) {
      const authorization = await getChannelAuthorizationFromStore(tx, userId, candidateChannel.channelId);
      if (isVisibleChannelAuthorization(authorization)) affectedChannelIds.push(candidateChannel.channelId);
    }
    const uniqueAffectedChannelIds = [...new Set(affectedChannelIds)];
    await tx.update(devices).set({ revokedAt: new Date() }).where(eq(devices.id, deviceId));
    await tx.delete(sessions).where(eq(sessions.deviceId, deviceId));
    if (uniqueAffectedChannelIds.length > 0) {
      // Fail closed: no further messages are accepted until an authorized
      // manager distributes a fresh epoch without the revoked device.
      await requireChannelKeyRotation(tx, uniqueAffectedChannelIds);
    }
    return {
      boundSessionIds: boundSessions.map((session: { id: string }) => session.id),
      changed: true,
      affectedChannelIds: uniqueAffectedChannelIds,
    };
  }, (committed) => ({
    actorId: userId,
    action: committed.changed ? 'device.revoke' : 'device.revoke.replay',
    targetType: 'device',
    targetId: deviceId,
    details: { affectedChannelCount: committed.affectedChannelIds.length },
  }));
  return {
    sessionIds: result.boundSessionIds,
    affectedChannelIds: result.affectedChannelIds,
  };
}

async function findCurrentKeyChannels(
  store: any,
  deviceId: string,
): Promise<Array<{ channelId: string; workspaceId: string }>> {
  const result = await store.execute(sql`
    select distinct r.channel_id as "channelId", c.workspace_id as "workspaceId"
    from channel_key_epoch_recipients r
    inner join channel_key_epochs e
      on e.channel_id = r.channel_id and e.version = r.version
    inner join channels c on c.id = r.channel_id
    where r.device_id = ${deviceId}
      and e.status in ('active', 'pending')
  `);
  return result.rows as Array<{ channelId: string; workspaceId: string }>;
}

export async function getDeviceById(deviceId: string) {
  return db.query.devices.findFirst({ where: eq(devices.id, deviceId) });
}

export async function updateLastActive(deviceId: string) {
  const now = Date.now();
  if ((recentActivityWrites.get(deviceId) ?? 0) > now - ACTIVITY_WRITE_INTERVAL_MS) return;
  recentActivityWrites.set(deviceId, now);
  if (recentActivityWrites.size > 20_000) {
    const staleBefore = now - ACTIVITY_WRITE_INTERVAL_MS;
    for (const [id, timestamp] of recentActivityWrites) {
      if (timestamp <= staleBefore) recentActivityWrites.delete(id);
      if (recentActivityWrites.size <= 10_000) break;
    }
  }
  try {
    await db.update(devices)
      .set({ lastActiveAt: new Date(now) })
      .where(and(eq(devices.id, deviceId), isNull(devices.revokedAt)));
  } catch (error) {
    recentActivityWrites.delete(deviceId);
    throw error;
  }
}

function formatDevice(device: typeof devices.$inferSelect) {
  return {
    id: device.id,
    userId: device.userId,
    name: device.name,
    identityKey: device.identityKey,
    createdAt: device.createdAt.toISOString(),
    lastActiveAt: device.lastActiveAt?.toISOString() || null,
    revokedAt: device.revokedAt?.toISOString() || null,
  };
}
