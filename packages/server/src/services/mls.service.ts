import { validateMlsKeyPackage } from '../security/mls-package.js';
import { createHash } from 'node:crypto';
import { and, asc, eq, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import {
  serializeGroupKeyPackage,
  serializeMlsEpoch,
  type MlsEpoch,
  type GroupKeyPackage,
} from '@alparts/shared';
import { db } from '../db/index.js';
import { devices, mlsKeyPackages, mlsEpochs, channelKeyEpochs } from '../db/schema.js';
import { getKeyRecipients, getKeyRecipientsFromStore, lockKeyProtocol } from './key.service.js';
import { auditedTransaction } from '../middleware/audit.js';
import { verifyDevicePayloadSignature } from '../security/message.js';
import { lockWorkspaceForAuthorization } from './authorization.service.js';
import { channels } from '../db/schema.js';
import { directoryHead } from './directory.service.js';
import { MAX_KEY_RECIPIENTS } from '../security/limits.js';

export async function publishKeyPackage(
  channelId: string,
  userId: string,
  deviceId: string,
  version: number,
  pkg: Pick<GroupKeyPackage, 'packageId' | 'keyPackage' | 'signature'>,
) {
  await validateMlsKeyPackage(pkg.keyPackage, deviceId);
  return auditedTransaction(
    async (tx) => {
      await lockKeyProtocol(tx);
      const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
      if (!channel) throw new Error('CHANNEL_NOT_FOUND');
      await lockWorkspaceForAuthorization(tx, channel.workspaceId, 'share');
      const state = await getKeyRecipientsFromStore(
        tx as unknown as typeof db,
        channelId,
        userId,
        deviceId,
      );
      if (version !== state.nextVersion || !state.recipients.some((p) => p.deviceId === deviceId))
        throw new Error('MLS_CONFLICT');
      const [device] = await tx
        .select()
        .from(devices)
        .where(
          and(
            eq(devices.id, deviceId),
            eq(devices.userId, userId),
            isNull(devices.revokedAt),
            isNotNull(devices.approvedAt),
          ),
        )
        .for('share');
      if (
        !device ||
        !verifyDevicePayloadSignature(
          device.identityKey,
          serializeGroupKeyPackage(channelId, version, { ...pkg, deviceId }),
          pkg.signature,
        )
      )
        throw new Error('INVALID_MLS');
      const [existing] = await tx
        .select()
        .from(mlsKeyPackages)
        .where(
          and(
            eq(mlsKeyPackages.channelId, channelId),
            eq(mlsKeyPackages.version, version),
            eq(mlsKeyPackages.deviceId, deviceId),
          ),
        );
      if (existing) {
        if (existing.packageId === pkg.packageId && existing.keyPackage === pkg.keyPackage)
          return false;
        // The next unused version can replace an expired/lost package. Once an
        // epoch is committed, nextVersion advances and its roster is immutable.
        await tx
          .update(mlsKeyPackages)
          .set(pkg)
          .where(
            and(
              eq(mlsKeyPackages.channelId, channelId),
              eq(mlsKeyPackages.version, version),
              eq(mlsKeyPackages.deviceId, deviceId),
            ),
          );
        return true;
      }
      await tx.insert(mlsKeyPackages).values({ channelId, version, deviceId, ...pkg });
      return true;
    },
    () => ({
      actorId: userId,
      action: 'channel.mls.key_package',
      targetType: 'channel',
      targetId: channelId,
    }),
  );
}

export async function groupPackages(channelId: string, userId: string, deviceId: string) {
  const state = await getKeyRecipients(channelId, userId, deviceId);
  const ids = state.recipients.map((r) => r.deviceId);
  const rows = ids.length
    ? await db
        .select()
        .from(mlsKeyPackages)
        .where(
          and(
            eq(mlsKeyPackages.channelId, channelId),
            eq(mlsKeyPackages.version, state.nextVersion),
            inArray(mlsKeyPackages.deviceId, ids),
          ),
        )
        .orderBy(asc(mlsKeyPackages.deviceId))
        .limit(MAX_KEY_RECIPIENTS)
    : [];
  return rows.map((row) => {
    const device = state.recipients.find((r) => r.deviceId === row.deviceId)!;
    return {
      deviceId: row.deviceId,
      userId: device.userId,
      identityKey: device.identityKey,
      packageId: row.packageId,
      keyPackage: row.keyPackage,
      signature: row.signature,
    };
  });
}

export async function validateAndStoreMlsEpoch(
  tx: any,
  epoch: MlsEpoch,
  eligible: Array<{ id: string; userId: string; identityKey: string }>,
  activeVersion: number,
) {
  if (
    epoch.previousVersion !== activeVersion ||
    epoch.roster.length !== eligible.length ||
    new Set(epoch.roster.map((r) => r.deviceId)).size !== eligible.length
  )
    throw new Error('INVALID_MLS');
  const [parent] = activeVersion
    ? await tx
        .select()
        .from(mlsEpochs)
        .where(and(eq(mlsEpochs.channelId, epoch.channelId), eq(mlsEpochs.version, activeVersion)))
    : [];
  if (epoch.previousTranscript !== (parent?.transcript ?? '0'.repeat(64)))
    throw new Error('MLS_CONFLICT');
  const userIds = [...new Set(eligible.map((p) => p.userId))].sort();
  if (epoch.directoryHeads.length !== userIds.length) throw new Error('INVALID_MLS');
  for (let i = 0; i < userIds.length; i++) {
    const actual = await directoryHead(tx, userIds[i]);
    const head = epoch.directoryHeads[i];
    if (
      head.userId !== actual.userId ||
      head.sequence !== actual.sequence ||
      head.hash !== actual.hash
    )
      throw new Error('MLS_CONFLICT');
  }
  const packages = await tx
    .select()
    .from(mlsKeyPackages)
    .where(
      and(eq(mlsKeyPackages.channelId, epoch.channelId), eq(mlsKeyPackages.version, epoch.version)),
    )
    .limit(MAX_KEY_RECIPIENTS + 1);
  for (const member of eligible) {
    const supplied = epoch.roster.find((p) => p.deviceId === member.id);
    const published = packages.find((p: any) => p.deviceId === member.id);
    if (
      !supplied ||
      !published ||
      supplied.userId !== member.userId ||
      supplied.identityKey !== member.identityKey ||
      supplied.packageId !== published.packageId ||
      supplied.keyPackage !== published.keyPackage ||
      supplied.signature !== published.signature
    )
      throw new Error('INVALID_MLS');
    await validateMlsKeyPackage(supplied.keyPackage, member.id);
  }
  const distributor = eligible.find((p) => p.id === epoch.distributorDeviceId);
  if (
    !distributor ||
    !verifyDevicePayloadSignature(
      distributor.identityKey,
      serializeMlsEpoch(epoch),
      epoch.signature,
    )
  )
    throw new Error('INVALID_MLS');
  const transcript = createHash('sha256').update(serializeMlsEpoch(epoch)).digest('hex');
  await tx.insert(mlsEpochs).values({
    channelId: epoch.channelId,
    version: epoch.version,
    transcript,
    envelope: epoch,
  });
  for (const head of epoch.directoryHeads) {
    await tx.execute(sql`insert into channel_directory_heads (channel_id, user_id, sequence)
      values (${epoch.channelId}, ${head.userId}, ${head.sequence})
      on conflict (channel_id, user_id) do update set sequence = greatest(channel_directory_heads.sequence, excluded.sequence)`);
  }
}

export async function getMlsEpoch(
  channelId: string,
  userId: string,
  deviceId: string,
  version: number,
) {
  return db.transaction(async (tx) => {
    const channel = await tx.query.channels.findFirst({ where: eq(channels.id, channelId) });
    if (!channel) throw new Error('CHANNEL_NOT_FOUND');
    await lockWorkspaceForAuthorization(tx, channel.workspaceId, 'share');
    const state = await getKeyRecipientsFromStore(
      tx as unknown as typeof db,
      channelId,
      userId,
      deviceId,
    );
    if (!state.recipients.some((r) => r.deviceId === deviceId && r.userId === userId))
      throw new Error('DEVICE_APPROVAL_REQUIRED');
    const allowed = await tx.execute(sql`with recursive owned as (
      select e.version, e.envelope from mls_epochs e
      join channel_key_epoch_recipients r on r.channel_id = e.channel_id and r.version = e.version
      join channel_key_epochs k on k.channel_id = e.channel_id and k.version = e.version
      where e.channel_id = ${channelId} and r.device_id = ${deviceId} and r.user_id = ${userId}
        and k.status in ('active', 'retired', 'pending')
      order by e.version desc limit 1
    ), ancestors as (
      select version, envelope, 0 as depth from owned
      union all
      select p.version, p.envelope, a.depth + 1 from ancestors a
      join mls_epochs p on p.channel_id = ${channelId} and p.version = (a.envelope->>'previousVersion')::integer
      where a.depth < 128 and p.version < a.version
    ) select 1 where exists (select 1 from channel_key_epoch_recipients
      where channel_id = ${channelId} and version = ${version} and device_id = ${deviceId} and user_id = ${userId})
      or exists (select 1 from ancestors where version = ${version})`);
    // A newly approved device needs the active signed predecessor to build a
    // fresh proposal. Older unrelated/aborted proposals remain inaccessible.
    // Continuous groups (protocol 4) are read only through the commit log,
    // which limits each device to the versions it was a member of.
    const currentShortcut = version === state.currentVersion && state.protocolVersion === 3;
    if (!currentShortcut && !allowed.rows.length) throw new Error('MLS_NOT_FOUND');
    const epoch = await tx.query.channelKeyEpochs.findFirst({
      where: and(eq(channelKeyEpochs.channelId, channelId), eq(channelKeyEpochs.version, version)),
    });
    if (!epoch || epoch.protocolVersion > 3) throw new Error('MLS_NOT_FOUND');
    const row = await tx.query.mlsEpochs.findFirst({
      where: and(eq(mlsEpochs.channelId, channelId), eq(mlsEpochs.version, version)),
    });
    if (!row) throw new Error('MLS_NOT_FOUND');
    return { ...row, status: epoch.status };
  });
}
