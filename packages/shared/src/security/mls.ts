import type { DirectoryHead } from './account.js';
import { MAX_KEY_RECIPIENTS } from '../constants/index.js';
/** Continuous per-channel groups. Versions 1-3 remain readable history. */
export const GROUP_PROTOCOL_VERSION = 4;
export const MLS_CIPHERSUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
/** A key package for the fixed suite is about 412 base64 characters. */
export const MAX_MLS_KEY_PACKAGE_LENGTH = 1024;
/** Each added device contributes one Add proposal carrying its key package. */
export const MAX_MLS_COMMIT_LENGTH = MAX_KEY_RECIPIENTS * (MAX_MLS_KEY_PACKAGE_LENGTH + 16) + 8192;
/** Each added device contributes one encrypted group secret and one tree leaf. */
export const MAX_MLS_WELCOME_LENGTH = MAX_KEY_RECIPIENTS * (MAX_MLS_KEY_PACKAGE_LENGTH + 512) + 16_384;
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

/** Exporter label for keys derived from a continuous channel group. */
export const MLS_GROUP_EXPORTER_LABEL = 'alparts-channel-epoch-v2';
/** A channel group is named by its genesis key version. */
export function mlsGroupId(channelId: string, genesisVersion: number): string {
  return JSON.stringify(['alparts-channel-group', 1, channelId, genesisVersion]);
}
/** Each key version of a group derives its own key from the epoch's exporter. */
export function mlsExporterContext(groupId: string, version: number): string {
  return JSON.stringify([groupId, version]);
}
/** A one-time package a device publishes so that a member can add it. */
export interface MlsMemberPackage {
  deviceId: string;
  userId: string;
  identityKey: string;
  packageId: string;
  keyPackage: string;
  signature: string;
}
export function serializeMlsMemberPackage(
  channelId: string,
  pkg: Pick<MlsMemberPackage, 'deviceId' | 'packageId' | 'keyPackage'>,
): string {
  return JSON.stringify([
    'alparts-mls-member-package',
    1,
    channelId,
    pkg.deviceId,
    pkg.packageId,
    pkg.keyPackage,
  ]);
}
export interface MlsGroupMember {
  deviceId: string;
  userId: string;
  leafIndex: number;
}
export type MlsGroupCommitKind = 'create' | 'commit';
/**
 * One accepted change of a channel group. The server orders these by version;
 * the commit is always a PublicMessage so the server can check its proposals.
 */
export interface MlsGroupCommit {
  channelId: string;
  version: number;
  previousVersion: number;
  previousTranscript: string;
  groupId: string;
  epoch: number;
  kind: MlsGroupCommitKind;
  /** base64url(SHA-256(exporter key)), 43 characters. */
  keyCommitment: string;
  commit: string;
  /** MLSMessage(mls_welcome), or '' when nobody is added. */
  welcome: string;
  /** Add-proposal order. A 'create' lists its creator first (no Add proposal for it). */
  added: MlsMemberPackage[];
  /** Sorted device ids. */
  removed: string[];
  /** Roster after the commit, sorted by leaf index. */
  members: MlsGroupMember[];
  /** Current head of every user in members, sorted by user id. */
  directoryHeads: DirectoryHead[];
  committerDeviceId: string;
  signature: string;
}
/** The transcript of a version is the hex SHA-256 of this string. */
export function serializeMlsGroupCommit(commit: Omit<MlsGroupCommit, 'signature'>): string {
  return JSON.stringify([
    'alparts-mls-group-commit',
    1,
    MLS_CIPHERSUITE,
    commit.channelId,
    commit.version,
    commit.previousVersion,
    commit.previousTranscript,
    commit.groupId,
    commit.epoch,
    commit.kind,
    commit.keyCommitment,
    commit.commit,
    commit.welcome,
    commit.added.map((p) => [
      p.deviceId,
      p.userId,
      p.identityKey,
      p.packageId,
      p.keyPackage,
      p.signature,
    ]),
    commit.removed,
    commit.members.map((m) => [m.deviceId, m.userId, m.leafIndex]),
    commit.directoryHeads.map((h) => [h.userId, h.sequence, h.hash]),
    commit.committerDeviceId,
  ]);
}
