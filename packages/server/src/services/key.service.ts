import { actionPurpose } from '../security/action-purpose.js';
import { assertFreshStartStepUp, type StepUpProof } from './passkey.service.js';
import { createHash } from 'node:crypto';
import { GROUP_PROTOCOL_VERSION, serializeMlsEpoch, type MlsEpoch } from '@alparts/shared';
import { validateAndStoreMlsEpoch } from './mls.service.js';
import { and, asc, desc, eq, inArray, isNotNull, isNull, ne, or, sql } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import {
  attachments,
  channelKeyEpochRecipients,
  channelKeyEpochs,
  channelKeys,
  channels,
  devices,
  messages,
} from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { getChannelAuthorization } from '../middleware/rbac.js';
import {
  getChannelAuthorizationFromStore,
  getChannelViewerIdsFromStore,
  getWorkspaceAuthorizationFromSnapshot,
  isVisibleChannelAuthorization,
  loadWorkspaceAuthorizationSnapshot,
  lockChannelAuthorization,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';
import {
  verifyChannelKeyAcknowledgementSignature,
  verifyChannelKeyEpochAbortSignature,
  verifyChannelKeyFreshStartSignature,
  verifyChannelKeyWrapSignature,
} from '../security/message.js';
import {
  MAX_DEVICE_DIRECTORY_ENTRIES,
  MAX_DEVICE_DIRECTORY_LOOKUP_IDS,
  MAX_KEY_DELIVERIES_PER_FETCH,
  MAX_KEY_DELIVERIES_PER_HISTORY_BATCH,
  MAX_KEY_RECIPIENTS,
  MAX_KEY_VERSION_LOOKUP_IDS,
  MAX_LEGACY_KEY_VERSION_LOOKUP_IDS,
} from '../security/limits.js';
import {
  abortPendingChannelKeyEpochs,
  areRequiredRecipientsAcknowledged,
  hasRevokedEpochRecipient,
  nextChannelKeyVersion,
} from './key-epoch-state.js';
import { assertCurrentPasswordSnapshot } from './auth.service.js';
import { getEligibleDevicesFromStore, loadGroupSnapshot } from './mls-group-state.js';
import { describeGroupState, LAST_SEEN_INTERVAL_MS, type EligibleDevice } from './mls-group-rules.js';
import { touchGroupMember } from './mls-group-heartbeat.js';

const KEY_PROTOCOL_VERSION = 2;
const MAX_KEY_VERSION = 1_000_000;

interface WrappedKeyInput {
  deviceId: string;
  encryptedKey: string;
  signature: string;
}

interface FreshStartAuthorization {
  expectedPasswordHash?: string;
  stepUpProof?: StepUpProof;
  signature: string;
}

export async function getKeyRecipients(channelId: string, userId: string, senderDeviceId?: string) {
  const { state, ownLastSeenAt } = await db.transaction(async (tx) => {
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, channel.workspaceId, 'share');
    return readKeyRecipientState(tx as unknown as typeof db, channelId, userId, senderDeviceId);
  });
  // A member that reads the state is online; fresh start for idle groups
  // (§5.3.4 a) counts from this heartbeat.
  if (senderDeviceId && ownLastSeenAt && Date.now() - ownLastSeenAt.getTime() >= LAST_SEEN_INTERVAL_MS) {
    await touchGroupMember(channelId, senderDeviceId);
  }
  return state;
}

export async function getKeyRecipientsFromStore(store: typeof db, channelId: string, userId: string, senderDeviceId?: string) {
  return (await readKeyRecipientState(store, channelId, userId, senderDeviceId)).state;
}

async function readKeyRecipientState(store: typeof db, channelId: string, userId: string, senderDeviceId?: string) {
  const authorization = await getChannelAuthorizationFromStore(store, userId, channelId);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');
  const channel = await store.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel) throw new Error('CHANNEL_NOT_FOUND');

  const recipientUserIds = await getChannelViewerIdsFromStore(store, channel);
  const recipientDevices: EligibleDevice[] = recipientUserIds.length === 0 ? [] : await store
    .select({ id: devices.id, userId: devices.userId, identityKey: devices.identityKey })
    .from(devices)
    .where(and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
    .orderBy(asc(devices.id));
  if (recipientDevices.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_LIMIT');

  const snapshot = await loadGroupSnapshot(store, channelId, recipientDevices.map((device) => device.id));
  const activeEpoch = await store.query.channelKeyEpochs.findFirst({
    where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
  });
  // Pre-v4 holders stay visible for history; v4 members are the group roster.
  const activeAcknowledgements = activeEpoch && activeEpoch.protocolVersion < 4
    ? await store.query.channelKeyEpochRecipients.findMany({
      columns: { deviceId: true },
      where: and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, activeEpoch.version),
        isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
      ),
      limit: MAX_KEY_RECIPIENTS + 1,
    })
    : [];
  if (activeAcknowledgements.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  const hasRotationPermission = channel.type === 'dm'
    || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
  const nextVersion = nextChannelKeyVersion(snapshot.latestVersion);
  const { ownLastSeenAt, ...group } = describeGroupState(channelId, snapshot, recipientDevices, {
    userId,
    deviceId: senderDeviceId,
    hasRotationPermission,
    now: Date.now(),
  });

  return {
    state: {
      protocolVersion: activeEpoch?.protocolVersion ?? GROUP_PROTOCOL_VERSION,
      // Provisional epochs ended with group protocol 4; these stay for old clients.
      pendingProtocolVersion: null,
      currentVersion: activeEpoch?.version ?? 0,
      keyCommitment: activeEpoch?.keyCommitment ?? null,
      pendingVersion: null,
      pendingKeyCommitment: null,
      pendingInvalid: false,
      pendingAcknowledgedDeviceIds: [] as string[],
      pendingRequiredDeviceIds: [] as string[],
      nextVersion,
      rotationRequired: group.rotationRequired,
      historyRecoveryRequired: group.historyRecoveryRequired,
      canRotate: nextVersion <= MAX_KEY_VERSION && (group.canCommit || group.canCreate),
      canAbortPending: false,
      distributedDeviceIds: group.group
        ? group.group.members.map((member) => member.deviceId)
        : activeAcknowledgements.map((row) => row.deviceId),
      recipients: recipientDevices.map((device) => ({
        deviceId: device.id,
        userId: device.userId,
        identityKey: device.identityKey,
      })),
      group: group.group,
      ownMembership: group.ownMembership,
      pendingAddDeviceIds: group.pendingAddDeviceIds,
      requiredRemoveDeviceIds: group.requiredRemoveDeviceIds,
      updateRequired: group.updateRequired,
      ownLeafRefreshDue: group.ownLeafRefreshDue,
      canCommit: group.canCommit,
      canCreate: group.canCreate,
      genesisWaiting: group.genesisWaiting,
    },
    ownLastSeenAt,
  };
}

export async function getDeviceChannelKeys(
  channelId: string,
  userId: string,
  deviceId: string,
  requestedVersions?: readonly number[],
  includeLegacyWindow = false,
) {
  const authorization = await getChannelAuthorization(userId, channelId);
  if (!authorization) throw new Error('CHANNEL_NOT_FOUND');
  const device = await db.query.devices.findFirst({
    where: and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt), isNotNull(devices.approvedAt)),
  });
  if (!device) throw new Error('DEVICE_REQUIRED');

  if (requestedVersions && (
    requestedVersions.length < 1
    || requestedVersions.length > MAX_KEY_VERSION_LOOKUP_IDS
    || new Set(requestedVersions).size !== requestedVersions.length
  )) throw new Error('KEY_VERSION_LOOKUP_LIMIT');
  const epochRows = requestedVersions !== undefined
    ? await db.query.channelKeyEpochs.findMany({
      where: and(
        eq(channelKeyEpochs.channelId, channelId),
        inArray(channelKeyEpochs.version, [...requestedVersions]),
      ),
      limit: requestedVersions.length + 1,
    })
    : includeLegacyWindow
      ? await db.query.channelKeyEpochs.findMany({
        where: and(
          eq(channelKeyEpochs.channelId, channelId),
          inArray(channelKeyEpochs.status, ['active', 'pending', 'retired']),
        ),
        orderBy: [desc(channelKeyEpochs.version)],
        limit: MAX_LEGACY_KEY_VERSION_LOOKUP_IDS,
      })
      : await db.query.channelKeyEpochs.findMany({
        where: and(
          eq(channelKeyEpochs.channelId, channelId),
          inArray(channelKeyEpochs.status, ['active', 'pending']),
        ),
        orderBy: [desc(channelKeyEpochs.version)],
        limit: 3,
      });
  if (
    (requestedVersions && epochRows.length > requestedVersions.length)
    || (!requestedVersions && !includeLegacyWindow && epochRows.length > 2)
  ) {
    throw new Error('KEY_EPOCH_INVARIANT_EXCEEDED');
  }
  const versions = epochRows.map((epoch) => epoch.version);
  if (versions.length === 0) return [];
  const epochsByVersion = new Map(epochRows.map((epoch) => [epoch.version, epoch]));
  const recipientStates = await db.query.channelKeyEpochRecipients.findMany({
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.deviceId, deviceId),
      inArray(channelKeyEpochRecipients.version, versions),
    ),
    limit: versions.length + 1,
  });
  if (recipientStates.length > versions.length) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  const recipientStatesByVersion = new Map(recipientStates.map((recipient) => [recipient.version, recipient]));
  const mutableVersions = epochRows
    .filter((epoch) => epoch.status === 'active' || epoch.status === 'pending')
    .map((epoch) => epoch.version);
  const retiredRecipientVersions = recipientStates
    .filter((recipient) => epochsByVersion.get(recipient.version)?.status === 'retired')
    .map((recipient) => recipient.version);
  const acceptedDeliveryIds = recipientStates.flatMap((recipient) => (
    recipient.acceptedDeliveryId ? [recipient.acceptedDeliveryId] : []
  ));
  const legacyProtocolVersions = epochRows
    .filter((epoch) => epoch.protocolVersion === 1)
    .map((epoch) => epoch.version);
  const deliveryLimit = requestedVersions === undefined && !includeLegacyWindow
    ? MAX_KEY_DELIVERIES_PER_FETCH
    : MAX_KEY_DELIVERIES_PER_HISTORY_BATCH;
  const keys = await db.query.channelKeys.findMany({
    where: and(
      eq(channelKeys.channelId, channelId),
      eq(channelKeys.deviceId, deviceId),
      or(
        mutableVersions.length > 0 ? inArray(channelKeys.version, mutableVersions) : sql`false`,
        retiredRecipientVersions.length > 0 ? inArray(channelKeys.version, retiredRecipientVersions) : sql`false`,
        acceptedDeliveryIds.length > 0 ? inArray(channelKeys.id, acceptedDeliveryIds) : sql`false`,
        legacyProtocolVersions.length > 0
          ? and(inArray(channelKeys.version, legacyProtocolVersions), isNotNull(channelKeys.confirmedAt))
          : sql`false`,
      ),
    ),
    orderBy: [desc(channelKeys.version), asc(channelKeys.createdAt), asc(channelKeys.id)],
    limit: deliveryLimit + 1,
  });
  if (keys.length > deliveryLimit) throw new Error('KEY_DELIVERY_INVARIANT_EXCEEDED');
  const distributorIds = [...new Set(keys.flatMap((key) => key.distributorDeviceId ? [key.distributorDeviceId] : []))];
  const distributors = distributorIds.length === 0 ? [] : await db.query.devices.findMany({
    columns: { id: true, identityKey: true },
    where: inArray(devices.id, distributorIds),
    limit: deliveryLimit + 1,
  });
  if (distributors.length > deliveryLimit) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  const distributorKeys = new Map(distributors.map((candidate) => [candidate.id, candidate.identityKey]));

  return keys.flatMap((key) => {
    const epoch = epochsByVersion.get(key.version);
    const distributorIdentityKey = key.distributorDeviceId
      ? distributorKeys.get(key.distributorDeviceId)
      : undefined;
    if (
      !epoch
      || epoch.status === 'aborted'
      || !key.distributorDeviceId
      || !key.signature
      || !distributorIdentityKey
    ) return [];
    const recipientState = recipientStatesByVersion.get(key.version);
    const confirmedAt = recipientState?.acceptedDeliveryId === key.id
      ? recipientState.acknowledgedAt
      : epoch.protocolVersion === 1
        ? key.confirmedAt
        : null;
    return [{
      deliveryId: key.id,
      version: key.version,
      epochStatus: epoch.status,
      encryptedKey: key.encryptedKey,
      keyCommitment: epoch.keyCommitment,
      distributorDeviceId: key.distributorDeviceId,
      distributorIdentityKey,
      signature: key.signature,
      confirmedAt: confirmedAt?.toISOString() ?? null,
      createdAt: key.createdAt.toISOString(),
    }];
  });
}

export async function getChannelDeviceDirectory(
  channelId: string,
  userId: string,
  requestedDeviceIds?: readonly string[],
) {
  if (!await getChannelAuthorization(userId, channelId)) throw new Error('CHANNEL_NOT_FOUND');
  const recipientUserIds = await getRecipientUserIds(channelId);
  const requestedIds = requestedDeviceIds === undefined
    ? null
    : [...new Set(requestedDeviceIds)];
  const requestedCount = requestedDeviceIds?.length;
  if (requestedIds && (
    requestedIds.length < 1
    || requestedIds.length > MAX_DEVICE_DIRECTORY_LOOKUP_IDS
    || requestedIds.length !== requestedCount
  )) throw new Error('DEVICE_DIRECTORY_LOOKUP_LIMIT');

  // Pre-batched browser clients used an unscoped directory for history. Keep a
  // strictly bounded rollout bridge so an open old tab can still verify normal
  // history, while new clients always request at most 64 exact device ids.
  if (!requestedIds) {
    const currentDevices = recipientUserIds.length === 0 ? [] : await db.query.devices.findMany({
      columns: { id: true },
      where: and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt), isNotNull(devices.approvedAt)),
      limit: MAX_DEVICE_DIRECTORY_ENTRIES + 1,
    });
    if (currentDevices.length > MAX_DEVICE_DIRECTORY_ENTRIES) {
      throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
    }
    const historicalRows = await db.selectDistinct({ deviceId: messages.deviceId })
      .from(messages)
      .where(and(eq(messages.channelId, channelId), isNotNull(messages.deviceId)))
      .limit(MAX_DEVICE_DIRECTORY_ENTRIES + 1);
    const historicalAttachmentRows = await db.selectDistinct({ deviceId: attachments.signerDeviceId })
      .from(attachments)
      .where(and(eq(attachments.channelId, channelId), isNotNull(attachments.signerDeviceId)))
      .limit(MAX_DEVICE_DIRECTORY_ENTRIES + 1);
    if (
      historicalRows.length > MAX_DEVICE_DIRECTORY_ENTRIES
      || historicalAttachmentRows.length > MAX_DEVICE_DIRECTORY_ENTRIES
    ) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
    const historicalDistributorRows = await db.selectDistinct({ deviceId: channelKeyEpochs.distributorDeviceId })
      .from(channelKeyEpochs).where(and(eq(channelKeyEpochs.channelId, channelId), isNotNull(channelKeyEpochs.distributorDeviceId))).limit(MAX_DEVICE_DIRECTORY_ENTRIES + 1);
    if (historicalDistributorRows.length > MAX_DEVICE_DIRECTORY_ENTRIES) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
    const legacyDeviceIds = [...new Set([
      ...historicalDistributorRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
      ...currentDevices.map((candidate) => candidate.id),
      ...historicalRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
      ...historicalAttachmentRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
    ])];
    if (legacyDeviceIds.length > MAX_DEVICE_DIRECTORY_ENTRIES) {
      throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
    }
    if (legacyDeviceIds.length === 0) return [];
    const legacyDevices = await db.query.devices.findMany({
      where: inArray(devices.id, legacyDeviceIds),
      limit: MAX_DEVICE_DIRECTORY_ENTRIES + 1,
    });
    if (legacyDevices.length > MAX_DEVICE_DIRECTORY_ENTRIES) {
      throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
    }
    return legacyDevices.map((candidate) => ({
      deviceId: candidate.id,
      userId: candidate.userId,
      identityKey: candidate.identityKey,
    }));
  }

  const currentDevices = recipientUserIds.length === 0 ? [] : await db.query.devices.findMany({
    columns: { id: true },
    where: and(
      inArray(devices.id, requestedIds),
      inArray(devices.userId, recipientUserIds),
      isNull(devices.revokedAt), isNotNull(devices.approvedAt),
    ),
    limit: requestedIds.length + 1,
  });
  if (currentDevices.length > requestedIds.length) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  const historicalRows = await db.selectDistinct({ deviceId: messages.deviceId })
    .from(messages)
    .where(and(
      eq(messages.channelId, channelId),
      isNotNull(messages.deviceId),
      inArray(messages.deviceId, requestedIds),
    ))
    .limit(requestedIds.length + 1);
  if (historicalRows.length > requestedIds.length) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  const historicalAttachmentRows = await db.selectDistinct({ deviceId: attachments.signerDeviceId })
    .from(attachments)
    .where(and(
      eq(attachments.channelId, channelId),
      isNotNull(attachments.signerDeviceId),
      inArray(attachments.signerDeviceId, requestedIds),
    ))
    .limit(requestedIds.length + 1);
  if (historicalAttachmentRows.length > requestedIds.length) {
    throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  }
  const historicalDistributorRows = await db.selectDistinct({ deviceId: channelKeyEpochs.distributorDeviceId })
    .from(channelKeyEpochs).where(and(eq(channelKeyEpochs.channelId, channelId), inArray(channelKeyEpochs.distributorDeviceId, requestedIds))).limit(requestedIds.length + 1);
  if (historicalDistributorRows.length > requestedIds.length) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  const deviceIds = [...new Set([
    ...historicalDistributorRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
    ...currentDevices.map((candidate) => candidate.id),
    ...historicalRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
    ...historicalAttachmentRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
  ])];
  if (deviceIds.length === 0) return [];
  if (deviceIds.length > requestedIds.length) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  // Historical signing public keys remain verifiable after revocation or
  // membership loss. This directory is not a key-recipient grant.
  const rows = await db.query.devices.findMany({
    where: inArray(devices.id, deviceIds),
    limit: deviceIds.length + 1,
  });
  if (rows.length > deviceIds.length) throw new Error('DEVICE_DIRECTORY_INVARIANT_EXCEEDED');
  const byId = new Map(rows.map((candidate) => [candidate.id, candidate]));
  return requestedIds.flatMap((deviceId) => {
    const candidate = byId.get(deviceId);
    return candidate ? [{
      deviceId: candidate.id,
      userId: candidate.userId,
      identityKey: candidate.identityKey,
    }] : [];
  });
}

export async function distributeChannelKeys(
  channelId: string,
  userId: string,
  senderDeviceId: string,
  version: number,
  keyCommitment: string,
  wrappedKeys: WrappedKeyInput[],
) {
  return commitChannelKeyDistribution(
    channelId,
    userId,
    senderDeviceId,
    version,
    keyCommitment,
    wrappedKeys,
    null,
  );
}

async function commitChannelKeyDistribution(
  channelId: string,
  userId: string,
  senderDeviceId: string,
  version: number,
  keyCommitment: string,
  wrappedKeys: WrappedKeyInput[],
  freshStart: FreshStartAuthorization | null,
  mls?: MlsEpoch,
) {
  const result = await auditedTransaction<{
    version: number;
    recipientCount: number;
    insertedCount: number;
    workspaceId: string;
    mode: 'proposal' | 'delivery';
    historyRecovery: boolean;
    freshStart: boolean;
  }>(async (tx) => {
    await lockKeyProtocol(tx);
    const channelLocation = await tx.query.channels.findFirst({
      columns: { workspaceId: true },
      where: eq(channels.id, channelId),
    });
    if (!channelLocation) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, channelLocation.workspaceId, 'update');
    await lockChannelAuthorization(tx, channelId);
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel) throw new Error('CHANNEL_NOT_FOUND');
    const authorization = await getChannelAuthorizationFromStore(tx, userId, channel);
    if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');

    const eligible = await getEligibleDevicesFromStore(tx, channel);
    if (eligible.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_LIMIT');
    const eligibleById = new Map(eligible.map((candidate) => [candidate.id, candidate]));
    const senderDevice = eligibleById.get(senderDeviceId);
    if (!senderDevice || senderDevice.userId !== userId) throw new Error('DEVICE_REQUIRED');
    if (freshStart) {
      if (mls) {
        await assertFreshStartStepUp(tx, freshStart.stepUpProof, userId, senderDeviceId,
          actionPurpose('POST', `/api/channels/${channelId}/mls/epochs/fresh-start`, {
            epoch: mls, keys: wrappedKeys, freshStartSignature: freshStart.signature,
          }));
      }
      if (freshStart.expectedPasswordHash) await assertCurrentPasswordSnapshot(tx, userId, freshStart.expectedPasswordHash);
      if (!verifyChannelKeyFreshStartSignature(senderDevice.identityKey, {
        channelId,
        keyVersion: version,
        keyCommitment,
        deviceId: senderDeviceId,
      }, freshStart.signature)) throw new Error('INVALID_KEY_FRESH_START');
    }
    const suppliedIds = new Set(wrappedKeys.map((key) => key.deviceId));
    if (
      suppliedIds.size !== wrappedKeys.length
      || wrappedKeys.some((key) => !eligibleById.has(key.deviceId))
    ) throw new Error('INVALID_KEY_RECIPIENTS');
    for (const key of wrappedKeys) {
      if (!verifyChannelKeyWrapSignature(senderDevice.identityKey, {
        channelId,
        keyVersion: version,
        keyCommitment,
        recipientDeviceId: key.deviceId,
        encryptedKey: key.encryptedKey,
      }, key.signature)) throw new Error('INVALID_KEY_SIGNATURE');
    }

    const activeEpoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
    });
    const pendingEpoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'pending')),
    });
    const latestEpoch = await tx.query.channelKeyEpochs.findFirst({
      columns: { version: true },
      where: eq(channelKeyEpochs.channelId, channelId),
      orderBy: [desc(channelKeyEpochs.version)],
    });
    const nextVersion = nextChannelKeyVersion(latestEpoch?.version);
    const activeHasRevokedRecipient = activeEpoch
      ? await hasRevokedEpochRecipient(tx, channelId, activeEpoch.version)
      : false;
    const effectiveRotationRequired = channel.keyRotationRequired || activeHasRevokedRecipient || !!(activeEpoch && (activeEpoch.protocolVersion < 3 || Date.now() - activeEpoch.createdAt.getTime() >= 24 * 60 * 60_000 || !await isEpochRosterCurrent(tx, channel, activeEpoch.version)));
    const activeHasEligibleHolder = activeEpoch
      ? await hasAnyAcceptedEpochRecipient(tx, channelId, activeEpoch.version, [...eligibleById.keys()])
      : false;
    const historyRecoveryRequired = Boolean(
      activeEpoch && effectiveRotationRequired && !activeHasEligibleHolder
    );
    let restartedByMember = false;
    if (freshStart) {
      if (version !== nextVersion) throw new Error('KEY_FRESH_START_CONFLICT');
      if (activeEpoch && !effectiveRotationRequired && !historyRecoveryRequired) throw new Error('KEY_FRESH_START_NOT_REQUIRED');
      const hasRotationPermission = channel.type === 'dm'
        || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
      // No eligible device holds the active key: nothing more can be lost, so
      // any current viewer may restart the channel (after step-up) instead of
      // waiting for a manager. A manager's in-flight proposal is only replaced
      // once it has stalled.
      const orphanedChannel = historyRecoveryRequired
        && (!pendingEpoch || Date.now() - pendingEpoch.createdAt.getTime() >= 15 * 60_000);
      if (!hasRotationPermission && !orphanedChannel) throw new Error('KEY_FRESH_START_FORBIDDEN');
      restartedByMember = !hasRotationPermission;
      if (!activeEpoch && !pendingEpoch) throw new Error('KEY_FRESH_START_NOT_REQUIRED');
      if (
        activeEpoch
        && !pendingEpoch
        && await hasAcceptedEpoch(tx, channelId, activeEpoch.version, senderDeviceId)
      ) {
        throw new Error('KEY_FRESH_START_NOT_REQUIRED');
      }
      if (pendingEpoch) {
        const aborted = await abortPendingChannelKeyEpochs(tx, [channelId]);
        if (!aborted.includes(channelId)) throw new Error('KEY_ABORT_FAILED');
      }
    }

    if (version === nextVersion) {
      if (!mls) throw new Error('GROUP_PROTOCOL_REQUIRED');
      if (pendingEpoch && !freshStart) throw new Error('KEY_EPOCH_PENDING');
      if (
        version > MAX_KEY_VERSION
        || suppliedIds.size !== eligibleById.size
        || [...eligibleById.keys()].some((id) => !suppliedIds.has(id))
      ) throw new Error('INCOMPLETE_KEY_DISTRIBUTION');
      if (activeEpoch && !freshStart) {
        if (!effectiveRotationRequired) throw new Error('KEY_ROTATION_NOT_REQUIRED');
        const hasRotationPermission = channel.type === 'dm'
          || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
        // Match canRotate: an ordinary proposal needs an acknowledged holder,
        // or a manager when all eligible holders are gone. Other viewers must
        // use fresh-start, including its step-up and manager notification.
        const senderAcknowledged = await hasAcceptedEpoch(tx, channelId, activeEpoch.version, senderDeviceId);
        if (!senderAcknowledged && !(historyRecoveryRequired && hasRotationPermission)) {
          throw new Error('KEY_DISTRIBUTION_FORBIDDEN');
        }
      }

      if (mls) {
        if (mls.channelId !== channelId || mls.version !== version || mls.keyCommitment !== keyCommitment || mls.distributorDeviceId !== senderDeviceId) throw new Error('INVALID_MLS');
        await validateAndStoreMlsEpoch(tx, mls, eligible, activeEpoch?.version ?? 0);
        const transcript = createHash('sha256').update(serializeMlsEpoch(mls)).digest('hex');
        const locator = Buffer.from(JSON.stringify({ mls: 1, version, transcript })).toString('base64');
        if (wrappedKeys.some((key) => key.encryptedKey !== locator)) throw new Error('INVALID_MLS');
      }
      await tx.insert(channelKeyEpochs).values({
        channelId,
        version,
        protocolVersion: mls ? 3 : KEY_PROTOCOL_VERSION,
        status: 'pending',
        keyCommitment,
        distributorDeviceId: senderDeviceId,
      });
      await tx.insert(channelKeyEpochRecipients).values(eligible.map((recipient) => ({
        channelId,
        version,
        deviceId: recipient.id,
        userId: recipient.userId,
        // Every fresh epoch requires the complete committed roster to verify.
        requiredForActivation: true,
      })));
      const inserted = await tx.insert(channelKeys).values(wrappedKeys.map((key) => ({
        channelId,
        version,
        deviceId: key.deviceId,
        encryptedKey: key.encryptedKey,
        distributorDeviceId: senderDeviceId,
        signature: key.signature,
      }))).returning({ id: channelKeys.id });
      await tx.update(channels).set({ keyRotationRequired: true }).where(eq(channels.id, channelId));
      return {
        version,
        recipientCount: wrappedKeys.length,
        insertedCount: inserted.length,
        workspaceId: channel.workspaceId,
        mode: 'proposal' as const,
        historyRecovery: historyRecoveryRequired || Boolean(freshStart),
        freshStart: Boolean(freshStart),
        // Managers learn that earlier messages became unreadable when a member
        // (not a manager) restarted the channel. Not part of the API response.
        notifyManagerUserIds: restartedByMember ? await channelManagersToNotify(tx, channel.workspaceId, userId) : [],
      };
    }

    const epoch = pendingEpoch?.version === version
      ? pendingEpoch
      : activeEpoch?.version === version
        ? activeEpoch
        : null;
    if (!epoch || ![KEY_PROTOCOL_VERSION, 3].includes(epoch.protocolVersion)) throw new Error('INVALID_KEY_VERSION');
    if (epoch.protocolVersion === 3) throw new Error('GROUP_PROTOCOL_REQUIRED');
    if (epoch.keyCommitment !== keyCommitment) throw new Error('KEY_COMMITMENT_MISMATCH');

    const existingCandidates: Array<{
      deviceId: string;
      distributorDeviceId: string | null;
      encryptedKey: string;
      signature: string | null;
    }> = await tx.query.channelKeys.findMany({
      columns: {
        deviceId: true,
        distributorDeviceId: true,
        encryptedKey: true,
        signature: true,
      },
      where: and(
        eq(channelKeys.channelId, channelId),
        eq(channelKeys.version, version),
        inArray(channelKeys.deviceId, [...suppliedIds]),
        eq(channelKeys.distributorDeviceId, senderDeviceId),
      ),
      limit: suppliedIds.size + 1,
    });
    if (existingCandidates.length > suppliedIds.size) throw new Error('KEY_DELIVERY_INVARIANT_EXCEEDED');
    const newWrappedKeys: WrappedKeyInput[] = [];
    for (const key of wrappedKeys) {
      const existing = existingCandidates.find((candidate) => (
        candidate.deviceId === key.deviceId
        && candidate.distributorDeviceId === senderDeviceId
      ));
      if (!existing) {
        newWrappedKeys.push(key);
        continue;
      }
      // A delivery tuple is an immutable signed statement. Byte-identical
      // retries are harmless; a changed retry is always a conflict.
      if (existing.encryptedKey !== key.encryptedKey || existing.signature !== key.signature) {
        throw new Error('KEY_CANDIDATE_IMMUTABLE');
      }
    }
    if (newWrappedKeys.length > 0 && !await hasAcceptedEpoch(tx, channelId, version, senderDeviceId)) {
      throw new Error('KEY_DISTRIBUTION_FORBIDDEN');
    }

    // Legacy backfill cannot grant an epoch to someone outside its original
    // account roster. New members receive the next epoch only.
    if (epoch.status === 'active' && newWrappedKeys.length > 0) {
      if (channel.keyRotationRequired || activeHasRevokedRecipient) throw new Error('KEY_ROTATION_REQUIRED');
      const originalRecipients: Array<{ userId: string }> = await tx.query.channelKeyEpochRecipients.findMany({
        columns: { userId: true },
        where: and(eq(channelKeyEpochRecipients.channelId, channelId), eq(channelKeyEpochRecipients.version, version)),
        limit: MAX_KEY_RECIPIENTS + 1,
      });
      const originalUsers = new Set(originalRecipients.map((recipient) => recipient.userId));
      if (originalRecipients.length > MAX_KEY_RECIPIENTS
        || newWrappedKeys.some((key) => !originalUsers.has(eligibleById.get(key.deviceId)!.userId))) throw new Error('INVALID_KEY_RECIPIENTS');
      await tx.insert(channelKeyEpochRecipients).values(newWrappedKeys.map((key) => {
        const recipient = eligibleById.get(key.deviceId)!;
        return {
          channelId,
          version,
          deviceId: key.deviceId,
          userId: recipient.userId,
          requiredForActivation: false,
        };
      })).onConflictDoNothing();
    }
    const newRecipientIds = newWrappedKeys.map((key) => key.deviceId);
    const targetRecipients: Array<typeof channelKeyEpochRecipients.$inferSelect> = newRecipientIds.length === 0
      ? []
      : await tx.query.channelKeyEpochRecipients.findMany({
        where: and(
          eq(channelKeyEpochRecipients.channelId, channelId),
          eq(channelKeyEpochRecipients.version, version),
          inArray(channelKeyEpochRecipients.deviceId, newRecipientIds),
        ),
        limit: newRecipientIds.length + 1,
      });
    if (
      targetRecipients.length !== newRecipientIds.length
      || targetRecipients.some((recipient) => (
        recipient.userId !== eligibleById.get(recipient.deviceId)?.userId
        || (epoch.status === 'pending' && !recipient.requiredForActivation)
      ))
    ) throw new Error('INVALID_KEY_RECIPIENTS');
    if (targetRecipients.some((recipient) => recipient.acceptedDeliveryId !== null)) {
      throw new Error('KEY_ALREADY_DISTRIBUTED');
    }

    const candidateCounts: Array<{ deviceId: string; count: number }> = newRecipientIds.length === 0 ? [] : await tx.select({
      deviceId: channelKeys.deviceId,
      count: sql<number>`count(*)::int`,
    }).from(channelKeys).where(and(
      eq(channelKeys.channelId, channelId),
      eq(channelKeys.version, version),
      inArray(channelKeys.deviceId, newRecipientIds),
    )).groupBy(channelKeys.deviceId).limit(newRecipientIds.length + 1);
    if (
      candidateCounts.length > newRecipientIds.length
      || candidateCounts.some((candidate) => Number(candidate.count) >= MAX_KEY_RECIPIENTS)
    ) {
      throw new Error('KEY_DELIVERY_LIMIT');
    }

    const inserted = newWrappedKeys.length === 0 ? [] : await tx.insert(channelKeys).values(
      newWrappedKeys.map((key) => ({
        channelId,
        version,
        deviceId: key.deviceId,
        encryptedKey: key.encryptedKey,
        distributorDeviceId: senderDeviceId,
        signature: key.signature,
      })),
    ).returning({ id: channelKeys.id });
    return {
      version,
      recipientCount: wrappedKeys.length,
      insertedCount: inserted.length,
      workspaceId: channel.workspaceId,
      mode: 'delivery' as const,
      historyRecovery: false,
      freshStart: false,
    };
  }, (committed) => ({
    actorId: userId,
    action: committed.freshStart
      ? 'channel.key.epoch.fresh_start'
      : committed.historyRecovery
      ? 'channel.key.epoch.recovery.propose'
      : committed.mode === 'proposal'
        ? 'channel.key.epoch.propose'
        : 'channel.key.delivery.add',
    targetType: 'channel',
    targetId: channelId,
    details: {
      workspaceId: committed.workspaceId,
      version,
      recipientCount: committed.recipientCount,
      insertedCount: committed.insertedCount,
      historyRecovery: committed.historyRecovery,
      freshStart: committed.freshStart,
    },
  }));
  return {
    version: result.version,
    recipientCount: result.recipientCount,
    insertedCount: result.insertedCount,
    mode: result.mode,
    historyRecovery: result.historyRecovery,
    freshStart: result.freshStart,
    workspaceId: result.workspaceId,
    notifyManagerUserIds: ('notifyManagerUserIds' in result ? result.notifyManagerUserIds : []) as string[],
  };
}

export async function acknowledgeChannelKey(
  channelId: string,
  userId: string,
  deviceId: string,
  deliveryId: string,
  signature: string,
) {
  return auditedTransaction(async (tx) => {
    await lockKeyProtocol(tx);
    const location = await tx.query.channels.findFirst({
      columns: { workspaceId: true },
      where: eq(channels.id, channelId),
    });
    if (!location) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, location.workspaceId, 'update');
    await lockChannelAuthorization(tx, channelId);
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
    const authorization = await getChannelAuthorizationFromStore(tx, userId, channel);
    if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');

    const [device] = await tx.select()
      .from(devices)
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
      .for('share');
    if (!device) throw new Error('DEVICE_REQUIRED');
    const delivery = await tx.query.channelKeys.findFirst({
      where: and(
        eq(channelKeys.id, deliveryId),
        eq(channelKeys.channelId, channelId),
        eq(channelKeys.deviceId, deviceId),
      ),
    });
    if (!delivery?.signature || !delivery.distributorDeviceId) throw new Error('INVALID_KEY_DELIVERY');
    const epoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(
        eq(channelKeyEpochs.channelId, channelId),
        eq(channelKeyEpochs.version, delivery.version),
      ),
    });
    if (
      !epoch
      || ![KEY_PROTOCOL_VERSION, 3].includes(epoch.protocolVersion)
      || (epoch.status !== 'pending' && epoch.status !== 'active' && epoch.status !== 'retired')
    ) throw new Error('INVALID_KEY_VERSION');
    const recipient = await tx.query.channelKeyEpochRecipients.findFirst({
      where: and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, delivery.version),
        eq(channelKeyEpochRecipients.deviceId, deviceId),
        eq(channelKeyEpochRecipients.userId, userId),
      ),
    });
    if (!recipient) throw new Error('INVALID_KEY_DELIVERY');
    if (!verifyChannelKeyAcknowledgementSignature(device.identityKey, {
      deliveryId,
      distributorDeviceId: delivery.distributorDeviceId,
      channelId,
      keyVersion: delivery.version,
      keyCommitment: epoch.keyCommitment,
      recipientDeviceId: deviceId,
      encryptedKey: delivery.encryptedKey,
    }, signature)) throw new Error('INVALID_KEY_ACKNOWLEDGEMENT');

    if (recipient.acceptedDeliveryId && recipient.acceptedDeliveryId !== deliveryId) {
      throw new Error('KEY_ALREADY_ACKNOWLEDGED');
    }
    const replay = recipient.acceptedDeliveryId === deliveryId;
    const acknowledgedAt = recipient.acknowledgedAt ?? new Date();
    if (!replay) {
      const updated = await tx.update(channelKeyEpochRecipients).set({
        acceptedDeliveryId: deliveryId,
        acknowledgementSignature: signature,
        acknowledgedAt,
      }).where(and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, delivery.version),
        eq(channelKeyEpochRecipients.deviceId, deviceId),
        isNull(channelKeyEpochRecipients.acceptedDeliveryId),
      )).returning({ deviceId: channelKeyEpochRecipients.deviceId });
      if (updated.length !== 1) throw new Error('KEY_ALREADY_ACKNOWLEDGED');
      // Compatibility-only mirror. New authorization reads the recipient's
      // exact acceptedDeliveryId and never trusts this timestamp by itself.
      await tx.update(channelKeys).set({ confirmedAt: acknowledgedAt }).where(and(
        eq(channelKeys.id, deliveryId),
        isNull(channelKeys.confirmedAt),
      ));
    }
    // Once the recipient selects an exact signed delivery, competing wraps
    // are no longer useful and retaining them only expands the attack/storage
    // surface. The accepted row is protected by the recipient foreign key.
    await tx.delete(channelKeys).where(and(
      eq(channelKeys.channelId, channelId),
      eq(channelKeys.version, delivery.version),
      eq(channelKeys.deviceId, deviceId),
      ne(channelKeys.id, deliveryId),
    ));

    let status = epoch.status;
    let activated = false;
    if (epoch.status === 'pending') {
      const epochRecipients = await tx.query.channelKeyEpochRecipients.findMany({
        where: and(
          eq(channelKeyEpochRecipients.channelId, channelId),
          eq(channelKeyEpochRecipients.version, epoch.version),
        ),
        limit: MAX_KEY_RECIPIENTS + 1,
      });
      if (epochRecipients.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
      if (areRequiredRecipientsAcknowledged(epochRecipients)) {
        const snapshotValid = await isRecipientSnapshotStillAuthorized(tx, channel, epochRecipients);
        if (!snapshotValid) {
          await abortPendingChannelKeyEpochs(tx, [channelId]);
          await tx.update(channels).set({ keyRotationRequired: true }).where(eq(channels.id, channelId));
          status = 'aborted';
        } else {
          const activatedAt = new Date();
          await tx.update(channelKeyEpochs).set({ status: 'retired' }).where(and(
            eq(channelKeyEpochs.channelId, channelId),
            eq(channelKeyEpochs.status, 'active'),
          ));
          const transitioned = await tx.update(channelKeyEpochs).set({
            status: 'active',
            activatedAt,
          }).where(and(
            eq(channelKeyEpochs.channelId, channelId),
            eq(channelKeyEpochs.version, epoch.version),
            eq(channelKeyEpochs.status, 'pending'),
          )).returning({ version: channelKeyEpochs.version });
          if (transitioned.length !== 1) throw new Error('KEY_ACTIVATION_FAILED');
          await tx.update(channels).set({ keyRotationRequired: false }).where(eq(channels.id, channelId));
          status = 'active';
          activated = true;
        }
      }
    }
    return {
      version: delivery.version,
      status,
      activated,
      acknowledgedAt,
      workspaceId: channel.workspaceId,
      replay,
    };
  }, (result) => ({
    actorId: userId,
    action: result.replay ? 'channel.key.acknowledge.replay' : 'channel.key.acknowledge',
    targetType: 'channel',
    targetId: channelId,
    details: {
      workspaceId: result.workspaceId,
      version: result.version,
      deviceId,
      deliveryId,
      activated: result.activated,
      status: result.status,
    },
  })).then((result) => ({
    version: result.version,
    status: result.status,
    activated: result.activated,
    confirmedAt: result.acknowledgedAt.toISOString(),
  }));
}

export async function abortPendingChannelKey(
  channelId: string,
  userId: string,
  deviceId: string,
  version: number,
  keyCommitment: string,
  signature: string,
) {
  return auditedTransaction(async (tx) => {
    await lockKeyProtocol(tx);
    const location = await tx.query.channels.findFirst({
      columns: { workspaceId: true },
      where: eq(channels.id, channelId),
    });
    if (!location) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, location.workspaceId, 'update');
    await lockChannelAuthorization(tx, channelId);
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
    const authorization = await getChannelAuthorizationFromStore(tx, userId, channel);
    if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');
    if (
      channel.type !== 'dm'
      && (authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS
    ) throw new Error('KEY_ABORT_FORBIDDEN');
    const [device] = await tx.select()
      .from(devices)
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
      .for('share');
    if (!device) throw new Error('DEVICE_REQUIRED');

    const epoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(
        eq(channelKeyEpochs.channelId, channelId),
        eq(channelKeyEpochs.version, version),
        eq(channelKeyEpochs.keyCommitment, keyCommitment),
      ),
    });
    if (!epoch || ![KEY_PROTOCOL_VERSION, 3].includes(epoch.protocolVersion)) throw new Error('INVALID_KEY_VERSION');
    if (!verifyChannelKeyEpochAbortSignature(device.identityKey, {
      channelId,
      keyVersion: version,
      keyCommitment,
      deviceId,
    }, signature)) throw new Error('INVALID_KEY_ABORT');
    if (epoch.status === 'aborted') {
      return { version, status: 'aborted', workspaceId: channel.workspaceId, replay: true };
    }
    if (epoch.status !== 'pending') throw new Error('INVALID_KEY_VERSION');
    const pendingRecipient = await tx.query.channelKeyEpochRecipients.findFirst({
      where: and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, version),
        eq(channelKeyEpochRecipients.deviceId, deviceId),
        eq(channelKeyEpochRecipients.userId, userId),
      ),
    });
    const pendingInvalid = await hasRevokedEpochRecipient(tx, channelId, version);
    const stalled = Date.now() - epoch.createdAt.getTime() >= 15 * 60_000;
    if (!pendingRecipient && !pendingInvalid && !stalled) throw new Error('KEY_ABORT_FORBIDDEN');

    const activeEpoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
    });
    if (
      activeEpoch
      && !stalled
      && epoch.distributorDeviceId !== deviceId
      && !await hasAcceptedEpoch(tx, channelId, activeEpoch.version, deviceId)
    ) {
      const eligible = await getEligibleDevicesFromStore(tx, channel);
      if (await hasAnyAcceptedEpochRecipient(
        tx,
        channelId,
        activeEpoch.version,
        eligible.map((candidate) => candidate.id),
      )) throw new Error('KEY_ABORT_FORBIDDEN');
    }
    const abortedChannelIds = await abortPendingChannelKeyEpochs(tx, [channelId]);
    if (!abortedChannelIds.includes(channelId)) throw new Error('KEY_ABORT_FAILED');
    await tx.update(channels).set({ keyRotationRequired: true }).where(eq(channels.id, channelId));
    return { version, status: 'aborted', workspaceId: channel.workspaceId, replay: false };
  }, (result) => ({
    actorId: userId,
    action: result.replay ? 'channel.key.epoch.abort.replay' : 'channel.key.epoch.abort',
    targetType: 'channel',
    targetId: channelId,
    details: { workspaceId: result.workspaceId, version, deviceId },
  })).then((result) => ({ version: result.version, status: result.status }));
}

async function getRecipientUserIds(channelId: string): Promise<string[]> {
  const channel = await db.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel) throw new Error('CHANNEL_NOT_FOUND');
  return getChannelViewerIdsFromStore(db, channel);
}

async function hasAcceptedEpoch(
  store: any,
  channelId: string,
  version: number,
  deviceId: string,
): Promise<boolean> {
  const recipient = await store.query.channelKeyEpochRecipients.findFirst({
    columns: { acceptedDeliveryId: true },
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, version),
      eq(channelKeyEpochRecipients.deviceId, deviceId),
      isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
    ),
  });
  return Boolean(recipient?.acceptedDeliveryId);
}

async function hasAnyAcceptedEpochRecipient(
  store: any,
  channelId: string,
  version: number,
  eligibleDeviceIds: readonly string[],
): Promise<boolean> {
  if (eligibleDeviceIds.length === 0) return false;
  if (eligibleDeviceIds.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_LIMIT');
  const recipient = await store.query.channelKeyEpochRecipients.findFirst({
    columns: { deviceId: true },
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, version),
      inArray(channelKeyEpochRecipients.deviceId, [...eligibleDeviceIds]),
      isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
    ),
  });
  return Boolean(recipient);
}

export async function channelManagersToNotify(store: any, workspaceId: string, actorId: string): Promise<string[]> {
  const snapshot = await loadWorkspaceAuthorizationSnapshot(store, workspaceId, []);
  if (!snapshot) return [];
  return [...snapshot.membersByUserId.keys()].filter((memberId) => {
    if (memberId === actorId) return false;
    if (snapshot.ownerId === memberId) return true;
    const authorization = getWorkspaceAuthorizationFromSnapshot(snapshot, memberId);
    return Boolean(authorization && (authorization.permissionMask & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS);
  }).sort();
}

async function isRecipientSnapshotStillAuthorized(
  store: any,
  channel: typeof channels.$inferSelect,
  recipients: Array<typeof channelKeyEpochRecipients.$inferSelect>,
): Promise<boolean> {
  if (recipients.length === 0) return false;
  const currentlyEligible = await getEligibleDevicesFromStore(store, channel);
  if (currentlyEligible.length !== recipients.length) return false;
  const activeById = new Map(currentlyEligible.map((candidate) => [candidate.id, candidate.userId]));
  return recipients.every((recipient) => (
    activeById.get(recipient.deviceId) === recipient.userId
  ));
}

async function lockKeyProtocol(store: any): Promise<void> {
  // Key distribution, acknowledgement, abort and revocation share one lock so
  // the epoch state and its bounded recipient/candidate sets change serially.
  await store.execute(sql`select pg_advisory_xact_lock(1095520322)`);
}

export { lockKeyProtocol };

export async function proposeMlsChannelEpoch(userId: string, deviceId: string, epoch: MlsEpoch, keys: WrappedKeyInput[], freshStartSignature?: string, stepUpProof?: StepUpProof) {
  return commitChannelKeyDistribution(epoch.channelId, userId, deviceId, epoch.version, epoch.keyCommitment, keys, freshStartSignature ? { signature: freshStartSignature, stepUpProof } : null, epoch);
}

export async function isEpochRosterCurrent(store: any, channel: typeof channels.$inferSelect, version: number): Promise<boolean> {
  const recipients = await store.query.channelKeyEpochRecipients.findMany({
    where: and(eq(channelKeyEpochRecipients.channelId, channel.id), eq(channelKeyEpochRecipients.version, version)),
    limit: MAX_KEY_RECIPIENTS + 1,
  });
  return recipients.length <= MAX_KEY_RECIPIENTS && isRecipientSnapshotStillAuthorized(store, channel, recipients);
}
