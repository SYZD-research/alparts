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
  isVisibleChannelAuthorization,
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
import {
  assertCurrentPasswordSnapshot,
  verifyCurrentPasswordSnapshot,
} from './auth.service.js';

const KEY_PROTOCOL_VERSION = 2;
const MAX_KEY_VERSION = 1_000_000;

interface EligibleDevice {
  id: string;
  userId: string;
  identityKey: string;
}

interface WrappedKeyInput {
  deviceId: string;
  encryptedKey: string;
  signature: string;
}

interface FreshStartAuthorization {
  expectedPasswordHash: string;
  signature: string;
}

export async function getKeyRecipients(channelId: string, userId: string, senderDeviceId?: string) {
  const authorization = await getChannelAuthorization(userId, channelId);
  if (!authorization) throw new Error('CHANNEL_NOT_FOUND');
  const channel = await db.query.channels.findFirst({ where: eq(channels.id, channelId) });
  if (!channel) throw new Error('CHANNEL_NOT_FOUND');

  const recipientUserIds = await getRecipientUserIds(channelId);
  const recipientDevices: EligibleDevice[] = recipientUserIds.length === 0 ? [] : await db
    .select({ id: devices.id, userId: devices.userId, identityKey: devices.identityKey })
    .from(devices)
    .where(and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt)))
    .orderBy(asc(devices.id));
  if (recipientDevices.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_LIMIT');

  const activeEpoch = await db.query.channelKeyEpochs.findFirst({
    where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
  });
  const pendingEpoch = await db.query.channelKeyEpochs.findFirst({
    where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'pending')),
  });
  const latestEpoch = await db.query.channelKeyEpochs.findFirst({
    columns: { version: true },
    where: eq(channelKeyEpochs.channelId, channelId),
    orderBy: [desc(channelKeyEpochs.version)],
  });

  const activeAcknowledgements = activeEpoch ? await db.query.channelKeyEpochRecipients.findMany({
    columns: { deviceId: true },
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, activeEpoch.version),
      isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
    ),
    limit: MAX_KEY_RECIPIENTS + 1,
  }) : [];
  if (activeAcknowledgements.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  const pendingRecipients = pendingEpoch ? await db.query.channelKeyEpochRecipients.findMany({
    columns: {
      deviceId: true,
      userId: true,
      requiredForActivation: true,
      acceptedDeliveryId: true,
    },
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, pendingEpoch.version),
    ),
    limit: MAX_KEY_RECIPIENTS + 1,
  }) : [];
  if (pendingRecipients.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  const senderPendingRecipient = pendingEpoch && senderDeviceId
    ? pendingRecipients.find((recipient) => (
      recipient.deviceId === senderDeviceId && recipient.userId === userId
    ))
    : null;

  const activeAcknowledgedDeviceIds = new Set(activeAcknowledgements.map((row) => row.deviceId));
  const activeHasRevokedRecipient = activeEpoch
    ? await hasRevokedEpochRecipient(db, channelId, activeEpoch.version)
    : false;
  const pendingHasRevokedRecipient = pendingEpoch
    ? await hasRevokedEpochRecipient(db, channelId, pendingEpoch.version)
    : false;
  const effectiveRotationRequired = channel.keyRotationRequired || activeHasRevokedRecipient;
  const activeHasEligibleHolder = recipientDevices.some((device) => (
    activeAcknowledgedDeviceIds.has(device.id)
  ));
  // If every accepted holder is gone, preserving the old epoch is impossible.
  // An authorized current device may create a fresh epoch for future writes;
  // old ciphertext remains unavailable and is never silently re-encrypted.
  const historyRecoveryRequired = Boolean(
    activeEpoch && effectiveRotationRequired && !activeHasEligibleHolder
  );
  const hasRotationPermission = channel.type === 'dm'
    || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
  const senderIsEligible = Boolean(senderDeviceId && recipientDevices.some(
    (device) => device.id === senderDeviceId && device.userId === userId,
  ));
  const nextVersion = nextChannelKeyVersion(latestEpoch?.version);
  const canRotate = Boolean(
    !pendingEpoch
    && nextVersion <= MAX_KEY_VERSION
    && hasRotationPermission
    && senderIsEligible
    && (
      !activeEpoch
      || (
        effectiveRotationRequired
        && senderDeviceId
        && (activeAcknowledgedDeviceIds.has(senderDeviceId) || historyRecoveryRequired)
      )
    )
  );
  const canAbortPending = Boolean(
    pendingEpoch
    && hasRotationPermission
    && senderIsEligible
    && (senderPendingRecipient || pendingHasRevokedRecipient)
    && (
      !activeEpoch
      || (senderDeviceId && activeAcknowledgedDeviceIds.has(senderDeviceId))
      || historyRecoveryRequired
      || pendingEpoch.distributorDeviceId === senderDeviceId
    )
  );

  return {
    currentVersion: activeEpoch?.version ?? 0,
    keyCommitment: activeEpoch?.keyCommitment ?? null,
    pendingVersion: pendingEpoch?.version ?? null,
    pendingKeyCommitment: pendingEpoch?.keyCommitment ?? null,
    pendingInvalid: pendingHasRevokedRecipient,
    pendingAcknowledgedDeviceIds: pendingRecipients.flatMap((recipient) => (
      recipient.acceptedDeliveryId ? [recipient.deviceId] : []
    )),
    pendingRequiredDeviceIds: pendingRecipients.flatMap((recipient) => (
      recipient.requiredForActivation ? [recipient.deviceId] : []
    )),
    nextVersion,
    rotationRequired: effectiveRotationRequired,
    historyRecoveryRequired,
    canRotate,
    canAbortPending,
    distributedDeviceIds: [...activeAcknowledgedDeviceIds],
    recipients: recipientDevices.map((device) => ({
      deviceId: device.id,
      userId: device.userId,
      identityKey: device.identityKey,
    })),
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
    where: and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)),
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
      where: and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt)),
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
    const legacyDeviceIds = [...new Set([
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
      isNull(devices.revokedAt),
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
  const deviceIds = [...new Set([
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

export async function startFreshChannelKey(
  channelId: string,
  userId: string,
  senderDeviceId: string,
  version: number,
  keyCommitment: string,
  wrappedKeys: WrappedKeyInput[],
  signature: string,
  currentPassword: string,
) {
  // Password work must finish before the audit/key/workspace locks below.
  const expectedPasswordHash = await verifyCurrentPasswordSnapshot(userId, currentPassword);
  return commitChannelKeyDistribution(
    channelId,
    userId,
    senderDeviceId,
    version,
    keyCommitment,
    wrappedKeys,
    { expectedPasswordHash, signature },
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
      await assertCurrentPasswordSnapshot(tx, userId, freshStart.expectedPasswordHash);
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
    const effectiveRotationRequired = channel.keyRotationRequired || activeHasRevokedRecipient;
    const activeHasEligibleHolder = activeEpoch
      ? await hasAnyAcceptedEpochRecipient(tx, channelId, activeEpoch.version, [...eligibleById.keys()])
      : false;
    const historyRecoveryRequired = Boolean(
      activeEpoch && effectiveRotationRequired && !activeHasEligibleHolder
    );
    if (freshStart) {
      if (version !== nextVersion) throw new Error('KEY_FRESH_START_CONFLICT');
      const hasRotationPermission = channel.type === 'dm'
        || (authorization.permissions & Permissions.MANAGE_CHANNELS) === Permissions.MANAGE_CHANNELS;
      if (!hasRotationPermission) throw new Error('KEY_FRESH_START_FORBIDDEN');
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
      if (pendingEpoch && !freshStart) throw new Error('KEY_EPOCH_PENDING');
      if (
        version > MAX_KEY_VERSION
        || suppliedIds.size !== eligibleById.size
        || [...eligibleById.keys()].some((id) => !suppliedIds.has(id))
      ) throw new Error('INCOMPLETE_KEY_DISTRIBUTION');
      if (
        channel.type !== 'dm'
        && (authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS
      ) throw new Error('KEY_ROTATION_FORBIDDEN');
      if (activeEpoch && !freshStart) {
        if (!effectiveRotationRequired) throw new Error('KEY_ROTATION_NOT_REQUIRED');
        if (
          !historyRecoveryRequired
          && !await hasAcceptedEpoch(tx, channelId, activeEpoch.version, senderDeviceId)
        ) {
          throw new Error('KEY_DISTRIBUTION_FORBIDDEN');
        }
      }

      await tx.insert(channelKeyEpochs).values({
        channelId,
        version,
        protocolVersion: KEY_PROTOCOL_VERSION,
        status: 'pending',
        keyCommitment,
        distributorDeviceId: senderDeviceId,
      });
      await tx.insert(channelKeyEpochRecipients).values(eligible.map((recipient) => ({
        channelId,
        version,
        deviceId: recipient.id,
        userId: recipient.userId,
        // A deliberately fresh conversation can become writable after the
        // initiating device verifies its exact committed delivery. Every
        // other currently authorized device still receives a signed wrap and
        // verifies it when next online, but no offline endpoint blocks writes.
        requiredForActivation: freshStart ? recipient.id === senderDeviceId : true,
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
      };
    }

    const epoch = pendingEpoch?.version === version
      ? pendingEpoch
      : activeEpoch?.version === version
        ? activeEpoch
        : null;
    if (!epoch || epoch.protocolVersion !== KEY_PROTOCOL_VERSION) throw new Error('INVALID_KEY_VERSION');
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

    // A pending epoch has a frozen required-recipient snapshot. Active epochs
    // may add a non-required recipient row for a newly registered device.
    if (epoch.status === 'active' && newWrappedKeys.length > 0) {
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
    await lockWorkspaceForAuthorization(tx, location.workspaceId, 'share');
    await lockChannelAuthorization(tx, channelId);
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel || channel.workspaceId !== location.workspaceId) throw new Error('CHANNEL_NOT_FOUND');
    const authorization = await getChannelAuthorizationFromStore(tx, userId, channel);
    if (!isVisibleChannelAuthorization(authorization)) throw new Error('CHANNEL_NOT_FOUND');

    const [device] = await tx.select()
      .from(devices)
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
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
      || epoch.protocolVersion !== KEY_PROTOCOL_VERSION
      || (epoch.status !== 'pending' && epoch.status !== 'active')
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
    await lockWorkspaceForAuthorization(tx, location.workspaceId, 'share');
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
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
      .for('share');
    if (!device) throw new Error('DEVICE_REQUIRED');

    const epoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(
        eq(channelKeyEpochs.channelId, channelId),
        eq(channelKeyEpochs.version, version),
        eq(channelKeyEpochs.keyCommitment, keyCommitment),
      ),
    });
    if (!epoch || epoch.protocolVersion !== KEY_PROTOCOL_VERSION) throw new Error('INVALID_KEY_VERSION');
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
    if (!pendingRecipient && !pendingInvalid) throw new Error('KEY_ABORT_FORBIDDEN');

    const activeEpoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
    });
    if (
      activeEpoch
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

async function getEligibleDevicesFromStore(
  store: any,
  channel: typeof channels.$inferSelect,
): Promise<EligibleDevice[]> {
  const recipientUserIds = await getChannelViewerIdsFromStore(store, channel);
  if (recipientUserIds.length === 0) return [];
  const result = await store.select({ id: devices.id, userId: devices.userId, identityKey: devices.identityKey })
    .from(devices)
    .where(and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt)))
    .orderBy(asc(devices.id))
    .limit(MAX_KEY_RECIPIENTS + 1)
    .for('share') as EligibleDevice[];
  if (result.length > MAX_KEY_RECIPIENTS) throw new Error('KEY_RECIPIENT_INVARIANT_EXCEEDED');
  return result;
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
