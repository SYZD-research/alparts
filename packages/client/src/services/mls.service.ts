import {
  serializeChannelKeyFreshStart,
  serializeChannelKeyWrap,
  serializeGroupKeyPackage,
  serializeMlsEpoch,
  type MlsEpoch,
  type GroupKeyPackage,
} from '@alparts/shared';
import { channelKeyScopes } from './channel-key-scope';
import { api, type ChannelKeyRecipientState } from './api';
import {
  getActiveDevice,
  signDevicePayload,
  verifyDevicePayload,
  ChannelKeyActivationPendingError,
} from './crypto.service';
import { verifiedDirectory, verifyDirectoryDevices } from './directory.service';
import {
  generateEpochKeyPackage,
  createEpochGroup,
  joinEpochGroup,
  decodePublicPackage,
  type EpochKeyPackage,
} from './mls-crypto';
import {
  readSecurityState,
  writeSecurityState,
  deleteSecurityState,
  listSecurityStateNames,
  sha256,
  toBase64,
  fromBase64,
} from './security-storage';
interface LocalPackage {
  packageId: string;
  material: EpochKeyPackage;
  createdAt: number;
  signature?: string;
}
const groupId = (epoch: Pick<MlsEpoch, 'channelId' | 'version' | 'previousTranscript'>) =>
  JSON.stringify(['alparts', epoch.channelId, epoch.version, epoch.previousTranscript]);
export async function prepareMlsPackage(channelId: string, version: number) {
  const owner = getActiveDevice();
  const scope = channelKeyScopes.capture(channelId);
  const save = (name: string, value: unknown) => writeSecurityState(owner, name, value, scope);
  const name = `mls-package:${channelId}:${version}`;
  return navigator.locks.request(`alparts-${name}:${owner.deviceId}`, async () => {
    await pruneOlderMlsPackages(owner, channelId, version);
    let stored = await readSecurityState<LocalPackage>(owner, name);
    if (!stored || Date.now() - stored.createdAt > 6 * 24 * 60 * 60_000) {
      stored = {
        packageId: crypto.randomUUID(),
        material: await generateEpochKeyPackage(owner.deviceId),
        createdAt: Date.now(),
      };
      await save(name, stored);
    }
    const pkg = {
      deviceId: owner.deviceId,
      packageId: stored.packageId,
      keyPackage: stored.material.publicPackage,
    };
    // ECDSA signatures vary on every call. Persist the signed package so an
    // unchanged publication does not look like a new roster to other tabs.
    if (!stored.signature) {
      stored.signature = await signDevicePayload(serializeGroupKeyPackage(channelId, version, pkg));
      await save(name, stored);
    }
    const signature = stored.signature;
    await api.securityRequest(`/channels/${channelId}/mls/packages`, {
      version,
      packageId: pkg.packageId,
      keyPackage: pkg.keyPackage,
      signature,
    });
    channelKeyScopes.assertCurrent(scope);
    return stored;
  });
}
const MAX_RETAINED_OLDER_MLS_PACKAGES = 8;
/**
 * Packages for abandoned epochs are never consumed. Keep only a bounded number
 * of older ones so a late welcome can still be joined.
 */
async function pruneOlderMlsPackages(owner: { userId: string; deviceId: string }, channelId: string, version: number) {
  const prefix = `mls-package:${channelId}:`;
  const older = (await listSecurityStateNames(owner, prefix, 256))
    .map((name) => Number(name.slice(prefix.length)))
    .filter((candidate) => Number.isSafeInteger(candidate) && candidate < version)
    .sort((left, right) => right - left);
  for (const stale of older.slice(MAX_RETAINED_OLDER_MLS_PACKAGES)) {
    await deleteSecurityState(owner, `${prefix}${stale}`);
    await deleteSecurityState(owner, `mls-proposal:${channelId}:${stale}`);
  }
}
async function validateRoster(epoch: MlsEpoch) {
  if (
    epoch.roster.length < 1 ||
    epoch.roster.length > 400 ||
    new Set(epoch.roster.map((p) => p.deviceId)).size !== epoch.roster.length
  )
    throw new Error('INVALID_MLS_ROSTER');
  const userIds = [...new Set(epoch.roster.map((p) => p.userId))].sort();
  if (epoch.directoryHeads.length !== userIds.length) throw new Error('INVALID_MLS_ROSTER');
  for (let i = 0; i < userIds.length; i++) {
    const head = epoch.directoryHeads[i];
    if (head.userId !== userIds[i]) throw new Error('INVALID_MLS_ROSTER');
    const directory = await verifiedDirectory(head.userId, epoch.channelId, head);
    for (const member of epoch.roster.filter((p) => p.userId === head.userId)) {
      const trusted = directory.devices[member.deviceId];
      if (
        !trusted ||
        trusted.approvedSequence === null ||
        trusted.approvedSequence > head.sequence ||
        (trusted.revokedSequence !== null && trusted.revokedSequence <= head.sequence) ||
        trusted.identityKey !== member.identityKey
      )
        throw new Error('DIRECTORY_INVALID');
    }
  }
  for (const pkg of epoch.roster) {
    const decoded = decodePublicPackage(pkg.keyPackage);
    if (
      decoded.leafNode.credential.credentialType !== 'basic' ||
      new TextDecoder().decode(decoded.leafNode.credential.identity) !== pkg.deviceId ||
      !(await verifyDevicePayload(
        serializeGroupKeyPackage(epoch.channelId, epoch.version, pkg),
        pkg.signature,
        pkg.identityKey,
      ))
    )
      throw new Error('INVALID_MLS_PACKAGE');
  }
}
export async function proposeMlsEpoch(
  channelId: string,
  state: ChannelKeyRecipientState,
  freshStart = false,
) {
  const owner = getActiveDevice();
  const scope = channelKeyScopes.capture(channelId);
  const save = (name: string, value: unknown) => writeSecurityState(owner, name, value, scope);
  const local = await prepareMlsPackage(channelId, state.nextVersion);
  await verifyDirectoryDevices(channelId, state.recipients, true);
  const roster = await api.securityRequest<GroupKeyPackage[]>(
    `/channels/${channelId}/mls/packages`,
  );
  if (
    roster.length !== state.recipients.length ||
    state.recipients.some((p) => !roster.some((r) => r.deviceId === p.deviceId))
  )
    throw new ChannelKeyActivationPendingError(state.recipients.length - roster.length);
  const directoryHeads = [];
  for (const userId of [...new Set(roster.map((p) => p.userId))].sort())
    directoryHeads.push((await verifiedDirectory(userId, channelId)).head);
  const parent =
    state.currentVersion && state.protocolVersion === 3
      ? await api.securityRequest<{ transcript: string }>(
          `/channels/${channelId}/mls/epochs/${state.currentVersion}`,
        )
      : null;
  const context = {
    channelId,
    version: state.nextVersion,
    previousVersion: state.currentVersion,
    previousTranscript: parent?.transcript ?? '0'.repeat(64),
  };
  const material = await createEpochGroup(
    groupId(context),
    local.material,
    roster.map((p) => p.keyPackage),
  );
  try {
    const commitment = toBase64(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', material.raw as Uint8Array<ArrayBuffer>),
      ),
    )
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const unsigned = {
      ...context,
      keyCommitment: commitment,
      welcome: material.welcome,
      commit: material.commit,
      roster,
      directoryHeads,
      distributorDeviceId: owner.deviceId,
    };
    const epoch: MlsEpoch = {
      ...unsigned,
      signature: await signDevicePayload(serializeMlsEpoch(unsigned)),
    };
    await validateRoster(epoch);
    const transcript = await sha256(serializeMlsEpoch(epoch));
    const encryptedKey = toBase64(
      new TextEncoder().encode(JSON.stringify({ mls: 1, version: epoch.version, transcript })),
    );
    const keys = await Promise.all(
      roster.map(async (p) => ({
        deviceId: p.deviceId,
        encryptedKey,
        signature: await signDevicePayload(
          serializeChannelKeyWrap({
            channelId,
            keyVersion: epoch.version,
            keyCommitment: commitment,
            recipientDeviceId: p.deviceId,
            encryptedKey,
          }),
        ),
      })),
    );
    // Persist an exact proposal before sending. A lost response is reconciled by
    // transcript, never by generating another secret for the same proposal.
    await save(`mls-proposal:${channelId}:${epoch.version}`, {
      epoch,
      keys,
      transcript,
      raw: toBase64(material.raw),
    });
    const freshStartSignature = freshStart
      ? await signDevicePayload(
          serializeChannelKeyFreshStart({
            channelId,
            keyVersion: epoch.version,
            keyCommitment: commitment,
            deviceId: owner.deviceId,
          }),
        )
      : undefined;
    await api.securityRequest(
      `/channels/${channelId}/mls/epochs${freshStart ? '/fresh-start' : ''}`,
      { epoch, keys, ...(freshStartSignature ? { freshStartSignature } : {}) },
    );
  } finally {
    material.raw.fill(0);
  }
}
export async function deriveMlsDelivery(
  channelId: string,
  version: number,
  transcript: string,
  deliveryStatus: string,
): Promise<Uint8Array> {
  const owner = getActiveDevice();
  const scope = channelKeyScopes.capture(channelId);
  const save = (name: string, value: unknown) => writeSecurityState(owner, name, value, scope);
  return navigator.locks.request(
    `alparts-mls-delivery:${owner.deviceId}:${channelId}`,
    async () => {
      const pinned = await readSecurityState<{
        version: number;
        transcript: string;
      }>(owner, `mls-head:${channelId}`);
      const cached = await readSecurityState<{
        raw: string;
        transcript: string;
      }>(owner, `mls-key:${channelId}:${version}`);
      if (
        (pinned?.version === version && pinned.transcript !== transcript) ||
        (cached && cached.transcript !== transcript) ||
        (deliveryStatus === 'active' && pinned && version < pinned.version)
      ) {
        throw new Error('INVALID_MLS_TRANSCRIPT');
      }
      // This authenticated local record was stored only after verifying the
      // complete signed envelope. An activated matching checkpoint makes that
      // immutable proof reusable; pending -> active still verifies and pins.
      if (
        cached &&
        (deliveryStatus === 'retired' ||
          (deliveryStatus === 'active' && pinned?.version === version))
      ) {
        channelKeyScopes.assertCurrent(scope);
        return fromBase64(cached.raw);
      }
      const response = await api.securityRequest<{
        envelope: MlsEpoch;
        transcript: string;
        status: string;
      }>(`/channels/${channelId}/mls/epochs/${version}`);
      const epoch = response.envelope;
      if (
        epoch.channelId !== channelId ||
        epoch.version !== version ||
        response.transcript !== transcript ||
        (await sha256(serializeMlsEpoch(epoch))) !== transcript
      )
        throw new Error('INVALID_MLS_TRANSCRIPT');
      const signer = epoch.roster.find((p) => p.deviceId === epoch.distributorDeviceId);
      if (
        !signer ||
        !(await verifyDevicePayload(serializeMlsEpoch(epoch), epoch.signature, signer.identityKey))
      )
        throw new Error('INVALID_MLS_SIGNATURE');
      await validateRoster(epoch);

      if (pinned && version > pinned.version) {
        let child = epoch;
        for (let page = 0; child.previousVersion > pinned.version && page < 128; page++) {
          const parent = await api.securityRequest<{
            envelope: MlsEpoch;
            transcript: string;
          }>(`/channels/${channelId}/mls/epochs/${child.previousVersion}`);
          const signer = parent.envelope.roster.find(
            (p) => p.deviceId === parent.envelope.distributorDeviceId,
          );
          if (
            parent.envelope.channelId !== channelId ||
            parent.envelope.version !== child.previousVersion ||
            parent.envelope.previousVersion >= parent.envelope.version ||
            parent.transcript !== child.previousTranscript ||
            (await sha256(serializeMlsEpoch(parent.envelope))) !== parent.transcript ||
            !signer ||
            !(await verifyDevicePayload(
              serializeMlsEpoch(parent.envelope),
              parent.envelope.signature,
              signer.identityKey,
            ))
          )
            throw new Error('INVALID_MLS_TRANSCRIPT');
          await validateRoster(parent.envelope);
          child = parent.envelope;
        }
        if (
          child.previousVersion !== pinned.version ||
          child.previousTranscript !== pinned.transcript
        )
          throw new Error('INVALID_MLS_TRANSCRIPT');
      }
      if (pinned && version === pinned.version && transcript !== pinned.transcript)
        throw new Error('INVALID_MLS_TRANSCRIPT');

      if (cached) {
        if (cached.transcript !== transcript) throw new Error('INVALID_MLS_TRANSCRIPT');
        if (response.status === 'active' && (!pinned || version > pinned.version))
          await save(`mls-head:${channelId}`, { version, transcript });
        channelKeyScopes.assertCurrent(scope);
        return fromBase64(cached.raw);
      }
      const self = epoch.roster.find((p) => p.deviceId === owner.deviceId);
      const local = await readSecurityState<LocalPackage>(
        owner,
        `mls-package:${channelId}:${version}`,
      );
      if (
        !self ||
        !local ||
        self.packageId !== local.packageId ||
        self.keyPackage !== local.material.publicPackage
      ) {
        // A verified final roster without this package can never use it.
        if (local && response.status !== 'pending') {
          await deleteSecurityState(owner, `mls-package:${channelId}:${version}`);
        }
        throw new Error('MLS_PACKAGE_UNAVAILABLE');
      }
      const proposal = await readSecurityState<{
        raw: string;
        transcript: string;
      }>(owner, `mls-proposal:${channelId}:${version}`);
      const raw =
        owner.deviceId === epoch.distributorDeviceId && proposal?.transcript === transcript
          ? fromBase64(proposal.raw)
          : await joinEpochGroup(
              groupId(epoch),
              local.material,
              epoch.roster.map((p) => p.keyPackage),
              epoch.welcome,
            );
      await save(`mls-key:${channelId}:${version}`, {
        raw: toBase64(raw),
        transcript,
      });
      if (response.status === 'active' && (!pinned || version > pinned.version))
        await save(`mls-head:${channelId}`, { version, transcript });
      await deleteSecurityState(owner, `mls-package:${channelId}:${version}`);
      await deleteSecurityState(owner, `mls-proposal:${channelId}:${version}`);
      channelKeyScopes.assertCurrent(scope);
      return raw;
    },
  );
}
export function mlsLocator(encryptedKey: string): { version: number; transcript: string } | null {
  try {
    const value = JSON.parse(new TextDecoder().decode(fromBase64(encryptedKey)));
    return value.mls === 1 &&
      Number.isSafeInteger(value.version) &&
      /^[a-f0-9]{64}$/.test(value.transcript)
      ? value
      : null;
  } catch {
    return null;
  }
}
