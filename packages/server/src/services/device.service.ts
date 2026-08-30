import { and, asc, eq, gt, inArray, isNull, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import {
  channelKeyEpochs,
  channelKeyEpochRecipients,
  channels,
  devices,
  sessions,
  workspaceMembers,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import {
  canonicalDeviceIdentityKey,
  verifyDeviceChallengeSignature,
} from '../security/message.js';
import { deviceChallenges } from '../security/device-challenge.js';
import {
  MAX_ACTIVE_DEVICES_PER_USER,
  MAX_ACTIVE_SESSIONS_PER_USER,
  MAX_TOTAL_CHANNELS_PER_WORKSPACE,
  MAX_WORKSPACE_MEMBERSHIPS_PER_USER,
} from '../security/limits.js';
import {
  assertCurrentPasswordSnapshot,
  verifyCurrentPasswordSnapshot,
} from './auth.service.js';
import { lockKeyProtocol } from './key.service.js';
import {
  abortPendingChannelKeyEpochs,
} from './key-epoch-state.js';
import {
  getChannelAuthorizationFromSnapshot,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
  loadWorkspaceAuthorizationSnapshot,
} from './authorization.service.js';

const ACTIVITY_WRITE_INTERVAL_MS = 5 * 60 * 1000;
const MAX_IDENTITY_MATCH_SCAN = 1_024;
const MAX_RECENT_ACTIVITY_ENTRIES = 20_000;
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
  // Password verification is deliberately outside auditedTransaction. bcrypt
  // worker admission can wait for bounded CPU capacity and must never hold the
  // global audit commit gate, key-protocol lock, or database row locks.
  const passwordHashSnapshot = currentPassword
    ? await verifyCurrentPasswordSnapshot(userId, currentPassword)
    : null;
  const result = await auditedTransaction<{
    device: typeof devices.$inferSelect;
    created: boolean;
    dirtyWorkspaceIds: string[];
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
      return { device: active, created: false, dirtyWorkspaceIds: [] };
    }

    if (!passwordHashSnapshot) throw new Error('DEVICE_STEP_UP_REQUIRED');
    await assertCurrentPasswordSnapshot(tx, userId, passwordHashSnapshot);
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
    const dirtyWorkspaceIds = await abortPendingEpochsForNewDevice(tx, userId);
    return { device: inserted[0], created: true, dirtyWorkspaceIds };
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
    dirtyWorkspaceIds: result.dirtyWorkspaceIds,
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
    limit: MAX_ACTIVE_DEVICES_PER_USER + 1,
  });
  if (rows.length > MAX_ACTIVE_DEVICES_PER_USER) throw new Error('DEVICE_INVARIANT_EXCEEDED');
  return rows.map(formatDevice);
}

async function abortPendingEpochsForNewDevice(store: any, userId: string): Promise<string[]> {
  const membershipRows = await store.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  }) as Array<{ workspaceId: string }>;
  if (membershipRows.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
    throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }
  const workspaceIds = [...new Set(membershipRows.map((row) => row.workspaceId))].sort();
  for (const workspaceId of workspaceIds) {
    await lockWorkspaceForAuthorization(store, workspaceId, 'update');
  }
  if (workspaceIds.length === 0) return [];

  const dirtyWorkspaceIds: string[] = [];
  for (const workspaceId of workspaceIds) {
    // A workspace has a durable total-channel bound. Partitioning cleanup by
    // workspace prevents one tenant from consuming an account-global cap and
    // permanently denying a member the ability to enroll a replacement
    // device, while keeping every query and authorization snapshot bounded.
    const pendingRows = await store.selectDistinct({
      channelId: channelKeyEpochs.channelId,
    }).from(channelKeyEpochs)
      .innerJoin(channels, eq(channels.id, channelKeyEpochs.channelId))
      .innerJoin(channelKeyEpochRecipients, and(
        eq(channelKeyEpochRecipients.channelId, channelKeyEpochs.channelId),
        eq(channelKeyEpochRecipients.version, channelKeyEpochs.version),
        eq(channelKeyEpochRecipients.userId, userId),
      ))
      .where(and(
        eq(channels.workspaceId, workspaceId),
        eq(channelKeyEpochs.status, 'pending'),
      ))
      .orderBy(asc(channelKeyEpochs.channelId))
      .limit(MAX_TOTAL_CHANNELS_PER_WORKSPACE + 1) as Array<{ channelId: string }>;
    const pendingChannelIds = pendingRows.map((row) => row.channelId);
    if (pendingChannelIds.length > MAX_TOTAL_CHANNELS_PER_WORKSPACE) {
      throw new Error('CHANNEL_INVARIANT_EXCEEDED');
    }
    if (pendingChannelIds.length === 0) continue;
    const snapshot = await loadWorkspaceAuthorizationSnapshot(store, workspaceId, pendingChannelIds);
    if (!snapshot) throw new Error('WORKSPACE_NOT_FOUND');
    const visiblePendingChannelIds = snapshot.channels
      .filter((channel) => isVisibleChannelAuthorization(
        getChannelAuthorizationFromSnapshot(snapshot, userId, channel, {}, false),
      ))
      .map((channel) => channel.id);
    // Device gain changes the provisional recipient set, but standard Secure
    // semantics permit backfilling this device into the current active epoch.
    const aborted = await abortPendingChannelKeyEpochs(store, visiblePendingChannelIds);
    if (aborted.length > 0) dirtyWorkspaceIds.push(workspaceId);
  }
  return dirtyWorkspaceIds;
}

export async function revokeDevice(
  deviceId: string,
  userId: string,
): Promise<{ sessionIds: string[]; affectedWorkspaceIds: string[] }> {
  const result = await auditedTransaction<{
    boundSessionIds: string[];
    changed: boolean;
    affectedWorkspaceIds: string[];
  }>(async (tx) => {
    await lockKeyProtocol(tx);
    const [device] = await tx.select()
      .from(devices)
      .where(eq(devices.id, deviceId))
      .for('update');
    if (!device) throw new Error('DEVICE_NOT_FOUND');
    if (device.userId !== userId) throw new Error('NOT_AUTHORIZED');

    const boundSessions = await tx.query.sessions.findMany({
      columns: { id: true },
      where: and(
        eq(sessions.deviceId, deviceId),
        eq(sessions.userId, userId),
        gt(sessions.expiresAt, new Date()),
      ),
      limit: MAX_ACTIVE_SESSIONS_PER_USER + 1,
    }) as Array<{ id: string }>;
    if (boundSessions.length > MAX_ACTIVE_SESSIONS_PER_USER) throw new Error('SESSION_INVARIANT_EXCEEDED');
    const changed = device.revokedAt === null;
    const affectedWorkspaceIds = changed
      ? await findAffectedWorkspaceIds(tx, deviceId, userId)
      : [];
    if (changed) await tx.update(devices).set({ revokedAt: new Date() }).where(eq(devices.id, deviceId));
    // Replay also removes legacy/stale bound sessions and repairs any key
    // state left by a previously interrupted older release.
    await tx.delete(sessions).where(eq(sessions.deviceId, deviceId));
    return {
      boundSessionIds: boundSessions.map((session: { id: string }) => session.id),
      changed,
      affectedWorkspaceIds,
    };
  }, (committed) => ({
    actorId: userId,
    action: committed.changed ? 'device.revoke' : 'device.revoke.replay',
    targetType: 'device',
    targetId: deviceId,
    details: {
      affectedWorkspaceCount: committed.affectedWorkspaceIds.length,
      enforcement: 'channel-local-revoked-recipient-check',
    },
  }));
  return {
    sessionIds: result.boundSessionIds,
    affectedWorkspaceIds: result.affectedWorkspaceIds,
  };
}

async function findAffectedWorkspaceIds(
  store: any,
  deviceId: string,
  userId: string,
): Promise<string[]> {
  const rows = await store.selectDistinct({
    workspaceId: channels.workspaceId,
  }).from(channelKeyEpochRecipients)
    .innerJoin(channelKeyEpochs, and(
      eq(channelKeyEpochs.channelId, channelKeyEpochRecipients.channelId),
      eq(channelKeyEpochs.version, channelKeyEpochRecipients.version),
    ))
    .innerJoin(channels, eq(channels.id, channelKeyEpochRecipients.channelId))
    .innerJoin(workspaceMembers, and(
      eq(workspaceMembers.workspaceId, channels.workspaceId),
      eq(workspaceMembers.userId, userId),
    ))
    .where(and(
      eq(channelKeyEpochRecipients.deviceId, deviceId),
      eq(channelKeyEpochRecipients.userId, userId),
      inArray(channelKeyEpochs.status, ['active', 'pending']),
    ))
    .orderBy(asc(channels.workspaceId))
    .limit(MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1) as Array<{ workspaceId: string }>;
  if (rows.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
    throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }
  return rows.map((row) => row.workspaceId);
}

export async function getDeviceById(deviceId: string) {
  return db.query.devices.findFirst({ where: eq(devices.id, deviceId) });
}

export async function updateLastActive(deviceId: string) {
  const now = Date.now();
  if ((recentActivityWrites.get(deviceId) ?? 0) > now - ACTIVITY_WRITE_INTERVAL_MS) return;
  if (!recentActivityWrites.has(deviceId) && recentActivityWrites.size >= MAX_RECENT_ACTIVITY_ENTRIES) {
    const staleBefore = now - ACTIVITY_WRITE_INTERVAL_MS;
    for (const [id, timestamp] of recentActivityWrites) {
      if (timestamp <= staleBefore) recentActivityWrites.delete(id);
      if (recentActivityWrites.size < MAX_RECENT_ACTIVITY_ENTRIES) break;
    }
    // Activity timestamps are advisory. When the exact memory cap is still
    // occupied by recently active devices, omit this write instead of turning
    // the coalescing cache into an attacker-controlled unbounded map.
    if (recentActivityWrites.size >= MAX_RECENT_ACTIVITY_ENTRIES) return;
  }
  recentActivityWrites.set(deviceId, now);
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
