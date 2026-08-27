import { and, asc, desc, eq, inArray, isNotNull, isNull, ne, sql } from 'drizzle-orm';
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
  verifyChannelKeyWrapSignature,
} from '../security/message.js';
import { MAX_KEY_RECIPIENTS } from '../security/limits.js';
import {
  abortPendingChannelKeyEpochs,
  areRequiredRecipientsAcknowledged,
  nextChannelKeyVersion,
} from './key-epoch-state.js';

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
  }) : [];
  const pendingAcknowledgements = pendingEpoch ? await db.query.channelKeyEpochRecipients.findMany({
    columns: { deviceId: true },
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.version, pendingEpoch.version),
      isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
    ),
  }) : [];
  const senderPendingRecipient = pendingEpoch && senderDeviceId
    ? await db.query.channelKeyEpochRecipients.findFirst({
      columns: { deviceId: true },
      where: and(
        eq(channelKeyEpochRecipients.channelId, channelId),
        eq(channelKeyEpochRecipients.version, pendingEpoch.version),
        eq(channelKeyEpochRecipients.deviceId, senderDeviceId),
        eq(channelKeyEpochRecipients.userId, userId),
      ),
    })
    : null;

  const activeAcknowledgedDeviceIds = new Set(activeAcknowledgements.map((row) => row.deviceId));
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
      || (channel.keyRotationRequired && senderDeviceId && activeAcknowledgedDeviceIds.has(senderDeviceId))
    )
  );
  const canAbortPending = Boolean(
    pendingEpoch
    && hasRotationPermission
    && senderIsEligible
    && senderPendingRecipient
    && (!activeEpoch || (senderDeviceId && activeAcknowledgedDeviceIds.has(senderDeviceId)))
  );

  return {
    currentVersion: activeEpoch?.version ?? 0,
    keyCommitment: activeEpoch?.keyCommitment ?? null,
    pendingVersion: pendingEpoch?.version ?? null,
    pendingKeyCommitment: pendingEpoch?.keyCommitment ?? null,
    pendingAcknowledgedDeviceIds: pendingAcknowledgements.map((row) => row.deviceId),
    nextVersion,
    rotationRequired: channel.keyRotationRequired,
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

export async function getDeviceChannelKeys(channelId: string, userId: string, deviceId: string) {
  const authorization = await getChannelAuthorization(userId, channelId);
  if (!authorization) throw new Error('CHANNEL_NOT_FOUND');
  const device = await db.query.devices.findFirst({
    where: and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)),
  });
  if (!device) throw new Error('DEVICE_REQUIRED');

  const keys = await db.query.channelKeys.findMany({
    where: and(eq(channelKeys.channelId, channelId), eq(channelKeys.deviceId, deviceId)),
    orderBy: [desc(channelKeys.version), asc(channelKeys.createdAt), asc(channelKeys.id)],
  });
  const versions = [...new Set(keys.map((key) => key.version))];
  const epochs = versions.length === 0 ? [] : await db.query.channelKeyEpochs.findMany({
    where: and(eq(channelKeyEpochs.channelId, channelId), inArray(channelKeyEpochs.version, versions)),
  });
  const epochsByVersion = new Map(epochs.map((epoch) => [epoch.version, epoch]));
  const recipientStates = versions.length === 0 ? [] : await db.query.channelKeyEpochRecipients.findMany({
    where: and(
      eq(channelKeyEpochRecipients.channelId, channelId),
      eq(channelKeyEpochRecipients.deviceId, deviceId),
      inArray(channelKeyEpochRecipients.version, versions),
    ),
  });
  const recipientStatesByVersion = new Map(recipientStates.map((recipient) => [recipient.version, recipient]));
  const distributorIds = [...new Set(keys.flatMap((key) => key.distributorDeviceId ? [key.distributorDeviceId] : []))];
  const distributors = distributorIds.length === 0 ? [] : await db.query.devices.findMany({
    columns: { id: true, identityKey: true },
    where: inArray(devices.id, distributorIds),
  });
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

export async function getChannelDeviceDirectory(channelId: string, userId: string) {
  if (!await getChannelAuthorization(userId, channelId)) throw new Error('CHANNEL_NOT_FOUND');
  const recipientUserIds = await getRecipientUserIds(channelId);
  const currentDevices = recipientUserIds.length === 0 ? [] : await db.query.devices.findMany({
    columns: { id: true },
    where: and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt)),
  });
  const historicalRows = await db.selectDistinct({ deviceId: messages.deviceId })
    .from(messages)
    .where(and(eq(messages.channelId, channelId), isNotNull(messages.deviceId)));
  const historicalAttachmentRows = await db.selectDistinct({ deviceId: attachments.signerDeviceId })
    .from(attachments)
    .where(and(eq(attachments.channelId, channelId), isNotNull(attachments.signerDeviceId)));
  const deviceIds = [...new Set([
    ...currentDevices.map((candidate) => candidate.id),
    ...historicalRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
    ...historicalAttachmentRows.flatMap((row) => row.deviceId ? [row.deviceId] : []),
  ])];
  if (deviceIds.length === 0) return [];
  // Historical signing public keys remain verifiable after revocation or
  // membership loss. This directory is not a key-recipient grant.
  const rows = await db.query.devices.findMany({ where: inArray(devices.id, deviceIds) });
  return rows.map((candidate) => ({
    deviceId: candidate.id,
    userId: candidate.userId,
    identityKey: candidate.identityKey,
  }));
}

export async function distributeChannelKeys(
  channelId: string,
  userId: string,
  senderDeviceId: string,
  version: number,
  keyCommitment: string,
  wrappedKeys: WrappedKeyInput[],
) {
  const result = await auditedTransaction<{
    version: number;
    recipientCount: number;
    insertedCount: number;
    workspaceId: string;
    mode: 'proposal' | 'delivery';
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

    if (version === nextVersion) {
      if (pendingEpoch) throw new Error('KEY_EPOCH_PENDING');
      if (
        version > MAX_KEY_VERSION
        || suppliedIds.size !== eligibleById.size
        || [...eligibleById.keys()].some((id) => !suppliedIds.has(id))
      ) throw new Error('INCOMPLETE_KEY_DISTRIBUTION');
      if (
        channel.type !== 'dm'
        && (authorization.permissions & Permissions.MANAGE_CHANNELS) !== Permissions.MANAGE_CHANNELS
      ) throw new Error('KEY_ROTATION_FORBIDDEN');
      if (activeEpoch) {
        if (!channel.keyRotationRequired) throw new Error('KEY_ROTATION_NOT_REQUIRED');
        if (!await hasAcceptedEpoch(tx, channelId, activeEpoch.version, senderDeviceId)) {
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
      ),
    });
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

    for (const recipientId of newRecipientIds) {
      const candidates = existingCandidates.filter((candidate) => candidate.deviceId === recipientId);
      if (candidates.length >= MAX_KEY_RECIPIENTS) throw new Error('KEY_DELIVERY_LIMIT');
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
    };
  }, (committed) => ({
    actorId: userId,
    action: committed.mode === 'proposal' ? 'channel.key.epoch.propose' : 'channel.key.delivery.add',
    targetType: 'channel',
    targetId: channelId,
    details: {
      workspaceId: committed.workspaceId,
      version,
      recipientCount: committed.recipientCount,
      insertedCount: committed.insertedCount,
    },
  }));
  return {
    version: result.version,
    recipientCount: result.recipientCount,
    insertedCount: result.insertedCount,
    mode: result.mode,
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
      const requiredRecipients = await tx.query.channelKeyEpochRecipients.findMany({
        where: and(
          eq(channelKeyEpochRecipients.channelId, channelId),
          eq(channelKeyEpochRecipients.version, epoch.version),
          eq(channelKeyEpochRecipients.requiredForActivation, true),
        ),
      });
      if (areRequiredRecipientsAcknowledged(requiredRecipients)) {
        const snapshotValid = await isRequiredSnapshotStillAuthorized(tx, channel, requiredRecipients);
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
    if (!pendingRecipient) throw new Error('KEY_ABORT_FORBIDDEN');

    const activeEpoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.status, 'active')),
    });
    if (activeEpoch && !await hasAcceptedEpoch(tx, channelId, activeEpoch.version, deviceId)) {
      throw new Error('KEY_ABORT_FORBIDDEN');
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
  return store.select({ id: devices.id, userId: devices.userId, identityKey: devices.identityKey })
    .from(devices)
    .where(and(inArray(devices.userId, recipientUserIds), isNull(devices.revokedAt)))
    .orderBy(asc(devices.id))
    .for('share') as Promise<EligibleDevice[]>;
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

async function isRequiredSnapshotStillAuthorized(
  store: any,
  channel: typeof channels.$inferSelect,
  requiredRecipients: Array<typeof channelKeyEpochRecipients.$inferSelect>,
): Promise<boolean> {
  if (requiredRecipients.length === 0) return false;
  const currentlyEligible = await getEligibleDevicesFromStore(store, channel);
  if (currentlyEligible.length !== requiredRecipients.length) return false;
  const activeById = new Map(currentlyEligible.map((candidate) => [candidate.id, candidate.userId]));
  return requiredRecipients.every((recipient) => (
    activeById.get(recipient.deviceId) === recipient.userId
  ));
}

async function lockKeyProtocol(store: any): Promise<void> {
  // Key distribution, acknowledgement, abort and revocation share one lock so
  // the epoch state and its bounded recipient/candidate sets change serially.
  await store.execute(sql`select pg_advisory_xact_lock(1095520322)`);
}

export { lockKeyProtocol };
