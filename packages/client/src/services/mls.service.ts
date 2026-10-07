import {
  MAX_KEY_RECIPIENTS,
  serializeGroupKeyPackage,
  serializeMlsEpoch,
  type MlsEpoch,
} from '@alparts/shared';
import { channelKeyScopes } from './channel-key-scope';
import { api } from './api';
import { getActiveDevice, verifyDevicePayload } from './crypto.service';
import { verifiedDirectory } from './directory.service';
import { joinEpochGroup, decodePublicPackage, type EpochKeyPackage } from './mls-crypto';
import {
  readSecurityState,
  writeSecurityState,
  deleteSecurityState,
  sha256,
  toBase64,
  fromBase64,
} from './security-storage';

// Group protocol 3 (one group per version), kept to read history: new
// versions come from continuous channel groups (mls-group.service.ts).

interface LocalPackage {
  packageId: string;
  material: EpochKeyPackage;
  createdAt: number;
  signature?: string;
}
const groupId = (epoch: Pick<MlsEpoch, 'channelId' | 'version' | 'previousTranscript'>) =>
  JSON.stringify(['alparts', epoch.channelId, epoch.version, epoch.previousTranscript]);
async function validateRoster(epoch: MlsEpoch) {
  if (
    epoch.roster.length < 1 ||
    epoch.roster.length > MAX_KEY_RECIPIENTS ||
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
/**
 * Once this device has pinned an MLS head for a channel, every key from that
 * version on must come from MLS. Older versions may still be RSA deliveries,
 * so history from before the move to MLS stays readable.
 */
export function nonMlsDeliveryAllowed(pinnedVersion: number | null, version: number): boolean {
  return pinnedVersion === null || version < pinnedVersion;
}

/** The MLS head version this device pinned for the channel, if any. */
export async function pinnedMlsVersion(channelId: string): Promise<number | null> {
  const pinned = await readSecurityState<{ version: number }>(getActiveDevice(), `mls-head:${channelId}`);
  return typeof pinned?.version === 'number' ? pinned.version : null;
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
