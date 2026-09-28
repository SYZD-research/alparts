import type { DirectoryHead } from './account.js';
export const GROUP_PROTOCOL_VERSION = 3;
export const MLS_CIPHERSUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
export interface GroupKeyPackage {
  deviceId: string;
  userId: string;
  identityKey: string;
  packageId: string;
  keyPackage: string;
  signature: string;
}
export interface MlsEpoch {
  channelId: string;
  version: number;
  previousVersion: number;
  previousTranscript: string;
  keyCommitment: string;
  welcome: string;
  commit: string;
  roster: GroupKeyPackage[];
  directoryHeads: DirectoryHead[];
  distributorDeviceId: string;
  signature: string;
}
export function serializeGroupKeyPackage(
  channelId: string,
  version: number,
  pkg: Pick<GroupKeyPackage, 'deviceId' | 'packageId' | 'keyPackage'>,
): string {
  return JSON.stringify([
    'alparts-mls-key-package',
    1,
    channelId,
    version,
    pkg.deviceId,
    pkg.packageId,
    pkg.keyPackage,
  ]);
}
export function serializeMlsEpoch(epoch: Omit<MlsEpoch, 'signature'>): string {
  return JSON.stringify([
    'alparts-mls-epoch',
    1,
    MLS_CIPHERSUITE,
    epoch.channelId,
    epoch.version,
    epoch.previousVersion,
    epoch.previousTranscript,
    epoch.keyCommitment,
    epoch.welcome,
    epoch.commit,
    epoch.roster.map((p) => [
      p.deviceId,
      p.userId,
      p.identityKey,
      p.packageId,
      p.keyPackage,
      p.signature,
    ]),
    epoch.directoryHeads.map((h) => [h.userId, h.sequence, h.hash]),
    epoch.distributorDeviceId,
  ]);
}
