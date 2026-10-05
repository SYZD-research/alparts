import {
  DIRECTORY_GENESIS,
  serializeDeviceChallengeProof,
  serializeDeviceDecision,
  serializeDirectoryEntry,
  type DirectoryEntry,
  type DirectoryHead,
} from '@alparts/shared';
import { sha256, fromBase64 } from './security-storage';
export interface VerifiedDirectory {
  verificationVersion: 2;
  migrationVerified: boolean;
  head: DirectoryHead;
  devices: Record<
    string,
    {
      identityKey: string;
      approved: boolean;
      revoked: boolean;
      approvedSequence: number | null;
      revokedSequence: number | null;
    }
  >;
  recovery: { generation: string; signingKey: string } | null;
  legacyClosed: boolean;
  checkpoints: Record<number, string>;
}
export function emptyDirectory(userId: string): VerifiedDirectory {
  return {
    verificationVersion: 2,
    migrationVerified: false,
    head: { userId, sequence: 0, hash: DIRECTORY_GENESIS },
    devices: {},
    recovery: null,
    legacyClosed: false,
    checkpoints: {},
  };
}
export async function verifyP256(
  payload: string,
  signature: string,
  jwk: JsonWebKey,
): Promise<boolean> {
  try {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d) return false;
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      fromBase64(signature),
      new TextEncoder().encode(payload),
    );
  } catch {
    return false;
  }
}
export async function verifyDirectoryEntries(
  previous: VerifiedDirectory,
  entries: DirectoryEntry[],
  migrationAnchor?: DirectoryHead,
): Promise<VerifiedDirectory> {
  const state = structuredClone(previous);
  if (entries.length > 64 || previous.head.sequence > 8192 || Object.keys(previous.devices).length > 1025) throw new Error('DIRECTORY_INVALID');
  for (const entry of entries) {
    const e = entry.event;
    if (
      entry.userId !== state.head.userId ||
      entry.sequence > 8192 ||
      entry.sequence !== state.head.sequence + 1 ||
      entry.previousHash !== state.head.hash ||
      (await sha256(serializeDirectoryEntry(entry))) !== entry.hash
    )
      throw new Error('DIRECTORY_INVALID');
    const target = state.devices[e.deviceId];
    const actor = state.devices[e.actorDeviceId];
    if (migrationAnchor && !state.migrationVerified && e.kind !== 'legacy')
      throw new Error('DIRECTORY_INVALID');
    if (e.kind === 'legacy') {
      if (
        !migrationAnchor ||
        migrationAnchor.userId !== entry.userId ||
        entry.sequence > migrationAnchor.sequence ||
        state.migrationVerified ||
        state.legacyClosed ||
        target ||
        e.actorDeviceId !== e.deviceId ||
        e.signature !== '' ||
        !['active', 'revoked'].includes(e.challenge ?? '')
      )
        throw new Error('DIRECTORY_INVALID');
      state.devices[e.deviceId] = {
        identityKey: e.identityKey,
        approved: false,
        revoked: e.challenge === 'revoked',
        approvedSequence: entry.sequence,
        revokedSequence: e.challenge === 'revoked' ? entry.sequence : null,
      };
      if (entry.sequence === migrationAnchor.sequence) {
        if (entry.hash !== migrationAnchor.hash) throw new Error('DIRECTORY_INVALID');
        for (const device of Object.values(state.devices)) device.approved = true;
        state.migrationVerified = true;
        state.legacyClosed = true;
      }
    } else {
      if (state.head.sequence > 0 && !state.legacyClosed && !state.migrationVerified)
        throw new Error('DIRECTORY_INVALID');
      state.legacyClosed = true;
      if (e.kind === 'register' || e.kind === 'bootstrap') {
        if (
          target ||
          e.actorDeviceId !== e.deviceId ||
          !e.challenge ||
          (e.kind === 'bootstrap' && entry.sequence !== 1) ||
          !(await verifyP256(
            serializeDeviceChallengeProof(entry.userId, e.challenge),
            e.signature,
            JSON.parse(e.identityKey).signingKey,
          ))
        )
          throw new Error('DIRECTORY_INVALID');
        state.devices[e.deviceId] = {
          identityKey: e.identityKey,
          approved: e.kind === 'bootstrap',
          revoked: false,
          approvedSequence: e.kind === 'bootstrap' ? entry.sequence : null,
          revokedSequence: null,
        };
      } else if (e.kind === 'recovery') {
        if (
          !state.recovery ||
          e.actorDeviceId !== state.recovery.generation ||
          !target ||
          target.revoked ||
          target.identityKey !== e.identityKey ||
          !(await verifyP256(
            serializeDeviceDecision(state.head, e),
            e.signature,
            JSON.parse(state.recovery.signingKey),
          ))
        )
          throw new Error('DIRECTORY_INVALID');
        target.approved = true;
        target.approvedSequence ??= entry.sequence;
      } else {
        if (
          !actor?.approved ||
          actor.revoked ||
          !(await verifyP256(
            serializeDeviceDecision(state.head, e),
            e.signature,
            JSON.parse(actor.identityKey).signingKey,
          ))
        )
          throw new Error('DIRECTORY_INVALID');
        if (e.kind === 'recovery-config') {
          if (state.recovery) throw new Error('DIRECTORY_INVALID');
          state.recovery = {
            generation: e.deviceId,
            signingKey: e.identityKey,
          };
        } else if (e.kind === 'recovery-disable') {
          if (
            state.recovery?.generation !== e.deviceId ||
            state.recovery.signingKey !== e.identityKey
          )
            throw new Error('DIRECTORY_INVALID');
          state.recovery = null;
        } else if (e.kind === 'approve' || e.kind === 'revoke') {
          if (
            !target ||
            target.revoked ||
            target.identityKey !== e.identityKey ||
            (e.kind === 'approve' && (target.approved || e.deviceId === e.actorDeviceId))
          )
            throw new Error('DIRECTORY_INVALID');
          if (e.kind === 'approve') {
            target.approved = true;
            target.approvedSequence = entry.sequence;
          } else {
            target.revoked = true;
            target.revokedSequence = entry.sequence;
          }
        } else throw new Error('DIRECTORY_INVALID');
      }
    }
    if (Object.keys(state.devices).length > 1025) throw new Error('DIRECTORY_INVALID');
    state.checkpoints[entry.sequence] = entry.hash;
    state.head = {
      userId: entry.userId,
      sequence: entry.sequence,
      hash: entry.hash,
    };
  }
  return state;
}

/**
 * What a device must be for its signature to count.
 * - `approved`: approved at some point. Past messages and attachments keep
 *   verifying after the device is revoked; a self-registered device that no
 *   approved device (or recovery) ever approved never qualifies.
 * - `active`: approved now and not revoked. New keys and call signaling.
 */
export type DeviceTrustPolicy = 'approved' | 'active';

export function deviceMeetsPolicy(
  recorded: { approved: boolean; revoked: boolean; approvedSequence: number | null },
  policy: DeviceTrustPolicy,
): boolean {
  const everApproved = recorded.approved || recorded.approvedSequence !== null;
  return policy === 'active' ? recorded.approved && !recorded.revoked : everApproved;
}
