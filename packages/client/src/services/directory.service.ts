import {
  serializeDeviceDecision,
  type Device,
  type DirectoryEntry,
  type DirectoryHead,
} from '@alparts/shared';
import { api } from './api';
import { getActiveDevice, signDevicePayload } from './crypto.service';
import { readSecurityState, writeSecurityState } from './security-storage';
// Reviewed migration heads are pinned in the application build, never fetched
// from the directory server whose legacy claims they authenticate.
import migrationAnchors from '../security/directory-migration-anchors.json';
import { emptyDirectory, verifyDirectoryEntries, type VerifiedDirectory, deviceMeetsPolicy, type DeviceTrustPolicy } from './directory-verifier';

export async function verifiedDirectory(
  userId: string,
  channelId?: string,
  expected?: DirectoryHead,
): Promise<VerifiedDirectory> {
  const owner = getActiveDevice();
  // Serialize checkpoint persistence across tabs as well as concurrent REST/WS work.
  return navigator.locks.request(
    `alparts-directory:${owner.userId}:${owner.deviceId}:${userId}`,
    async () => {
      let state =
        (await readSecurityState<VerifiedDirectory>(owner, `directory:${userId}`)) ??
        emptyDirectory(userId);
      const previousHead = state.head;
      if (state.verificationVersion !== 2) state = emptyDirectory(userId);
      const migrationAnchor = (migrationAnchors as Record<string, DirectoryHead>)[userId];
      const target =
        expected ??
        (
          await api.securityRequest<{ head: DirectoryHead }>(
            `/directory/${userId}?after=${state.head.sequence}${channelId ? `&channelId=${channelId}` : ''}`,
          )
        ).head;
      if (!Number.isSafeInteger(target.sequence) || target.sequence < 0 || target.sequence > 8192 || target.userId !== userId) throw new Error('DIRECTORY_INVALID');
      // A historical peer lookup may disclose a shorter, already verified prefix.
      if (target.sequence < state.head.sequence && state.checkpoints[target.sequence] === target.hash) return state;
      if (expected && expected.sequence <= state.head.sequence) {
        if (state.checkpoints[expected.sequence] !== expected.hash)
          throw new Error('DIRECTORY_INVALID');
        return state;
      }
      if (
        target.userId !== userId ||
        target.sequence < state.head.sequence ||
        (target.sequence === state.head.sequence && target.hash !== state.head.hash)
      )
        throw new Error('DIRECTORY_INVALID');
      for (let page = 0; state.head.sequence < target.sequence && page < 128; page++) {
        const response = await api.securityRequest<{
          head: DirectoryHead;
          entries: DirectoryEntry[];
        }>(
          `/directory/${userId}?after=${state.head.sequence}${channelId ? `&channelId=${channelId}` : ''}`,
        );
        const entries = response.entries.filter((entry) => entry.sequence <= target.sequence);
        if (!entries.length) throw new Error('DIRECTORY_INVALID');
        state = await verifyDirectoryEntries(state, entries, migrationAnchor);
      }
      if (state.head.sequence !== target.sequence || state.head.hash !== target.hash)
        throw new Error('DIRECTORY_INVALID');
      if (
        previousHead.sequence > 0 &&
        state.checkpoints[previousHead.sequence] !== previousHead.hash
      )
        throw new Error('DIRECTORY_INVALID');
      if (!state.legacyClosed && state.head.sequence > 0) throw new Error('DIRECTORY_INVALID');
      state.legacyClosed = true;
      await writeSecurityState(owner, `directory:${userId}`, state);
      return state;
    },
  );
}

/** This device's latest verified directory of a user, without contacting the server. */
export async function cachedDirectory(userId: string): Promise<VerifiedDirectory | null> {
  const state = await readSecurityState<VerifiedDirectory>(getActiveDevice(), `directory:${userId}`);
  return state?.verificationVersion === 2 ? state : null;
}

export async function verifyDirectoryDevices(
  channelId: string,
  devices: Array<{ deviceId: string; userId: string; identityKey: string }>,
  policy: DeviceTrustPolicy,
) {
  const users = [...new Set(devices.map((d) => d.userId))];
  for (const userId of users) {
    const state = await verifiedDirectory(userId, channelId);
    for (const device of devices.filter((d) => d.userId === userId)) {
      const recorded = state.devices[device.deviceId];
      if (
        !recorded ||
        recorded.identityKey !== device.identityKey ||
        !deviceMeetsPolicy(recorded, policy)
      )
        throw new Error('DIRECTORY_INVALID');
    }
  }
}
export async function deviceDecision(device: Device, kind: 'approve' | 'revoke') {
  const owner = getActiveDevice();
  const state = await verifiedDirectory(owner.userId);
  const recorded = state.devices[device.id];
  if (!recorded || recorded.identityKey !== device.identityKey)
    throw new Error('DIRECTORY_INVALID');
  const signature = await signDevicePayload(
    serializeDeviceDecision(state.head, {
      kind,
      deviceId: device.id,
      identityKey: device.identityKey,
      actorDeviceId: owner.deviceId,
    }),
  );
  return { head: state.head, signature };
}
