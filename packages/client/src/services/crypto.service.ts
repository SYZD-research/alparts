import {
  deleteChannelSecurityState,
  fromBase64,
  listSecurityStateNames,
  readSecurityState,
  writeSecurityState,
} from './security-storage';
import { padMessage, unpadMessage } from './message-padding';
import { deriveMlsDelivery, mlsLocator, nonMlsDeliveryAllowed, pinnedMlsVersion } from './mls.service';
import {
  cancelGroupMaintenance,
  createChannelGroupVersion,
  ensureChannelGroupKey,
  localGroupView,
  syncChannelGroup,
  type ChannelKeyPurpose,
} from './mls-group.service';
import { assertKeyRecipientState, isGroupEquivocation, requiresGroupKey } from './mls-group-model';
import { verifiedDirectory } from './directory.service';
import {
  serializeAttachmentEnvelope,
  serializeDeviceChallengeProof,
  serializeChannelKeyAcknowledgement,
  serializeChannelKeyWrap,
  serializeMessageAad,
  serializeMessageEnvelope,
  serializeVoiceKeyEnvelope,
  serializeVoiceSignalEnvelope,
  type SignedAttachmentEnvelope,
  type SignedMessageEnvelope,
  type SignedVoiceKeyEnvelope,
  type SignedVoiceSignalEnvelope,
  type User,
} from '@alparts/shared';
import {
  api,
  ApiError,
  type ChannelKeyDelivery,
  type ChannelKeyEpochStatus,
} from './api';
import { channelKeyScopes, type ChannelKeyScopeToken } from './channel-key-scope';
import {
  deleteDesktopSecret,
  getDesktopBridge,
  getDesktopSecret,
  setDesktopSecret,
} from './desktop.service';

const DB_NAME = 'alparts-crypto';
const STORE_NAME = 'keys';
const DB_VERSION = 3;

interface DevicePublicBundle {
  version: 1;
  encryptionKey: JsonWebKey;
  signingKey: JsonWebKey;
}

interface DesktopDevicePrivateBundle {
  version: 1;
  identityKey: string;
  encryptionPrivateKey: JsonWebKey;
  signingPrivateKey: JsonWebKey;
}

interface DeviceKeyMaterial {
  identityKey: string;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

interface DesktopSecretPointer {
  version: 1;
  desktopSecret: true;
}

interface ActiveDevice {
  approved: boolean;
  userId: string;
  deviceId: string;
  identityKey: string;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

export interface ChannelKey {
  key: CryptoKey;
  version: number;
}

export {
  CHANNEL_KEY_DELIVERY_PENDING,
  ChannelKeyDeliveryPendingError,
  channelKeyWait,
  isChannelKeyDeliveryPendingError,
  type ChannelKeyWait,
  type ChannelKeyWaitReason,
} from './channel-key-wait';
export { assertKeyRecipientState } from './mls-group-model';
export type { ChannelKeyPurpose } from './mls-group.service';

interface LoadedChannelKeyDelivery {
  key: CryptoKey;
  delivery: ChannelKeyDelivery;
  acknowledged: boolean;
}

let activeDevice: ActiveDevice | null = null;
const deviceInitializations = new Map<string, Promise<ActiveDevice>>();

const channelKeyDeletionQueues = new Map<string, Promise<void>>();

async function getDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const store = (event as IDBVersionChangeEvent).oldVersion === 0
        ? request.result.createObjectStore(STORE_NAME)
        : request.transaction!.objectStore(STORE_NAME);
      // Delete the legacy plaintext/extractable private-key record.
      store.delete('device-private-key');
      if ((event as IDBVersionChangeEvent).oldVersion < 3) {
        const cursorRequest = store.openCursor();
        cursorRequest.onsuccess = () => {
          const cursor = cursorRequest.result;
          if (!cursor) return;
          if (typeof cursor.key === 'string' && cursor.key.startsWith('channel:')) cursor.delete();
          cursor.continue();
        };
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveValue(key: string, value: unknown): Promise<void> {
  await saveValues([[key, value]]);
}

async function deleteValue(key: string): Promise<void> {
  const db = await getDb();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  tx.objectStore(STORE_NAME).delete(key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function saveValues(entries: Array<readonly [string, unknown]>): Promise<void> {
  const db = await getDb();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);
  for (const [key, value] of entries) store.put(value, key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function loadValue<T>(key: string): Promise<T | null> {
  const db = await getDb();
  const tx = db.transaction(STORE_NAME, 'readonly');
  const request = tx.objectStore(STORE_NAME).get(key);
  return new Promise((resolve, reject) => {
    request.onsuccess = () => { db.close(); resolve((request.result as T | undefined) ?? null); };
    request.onerror = () => { db.close(); reject(request.error); };
  });
}

function devicePrefix(userId: string): string {
  return `device:${userId}`;
}

export async function ensureDeviceSession(user: User, stepUpPassword?: string): Promise<ActiveDevice> {
  if (activeDevice?.userId === user.id) return activeDevice;
  const existing = deviceInitializations.get(user.id);
  if (existing) return existing;
  const initialization = initializeDeviceSession(user, stepUpPassword).finally(() => {
    if (deviceInitializations.get(user.id) === initialization) deviceInitializations.delete(user.id);
  });
  deviceInitializations.set(user.id, initialization);
  return initialization;
}

let deviceSessionGeneration = 0;

async function initializeDeviceSession(user: User, stepUpPassword?: string): Promise<ActiveDevice> {
  const generation = deviceSessionGeneration;
  const prefix = devicePrefix(user.id);
  let material = await loadDeviceKeyMaterial(user.id, prefix) ?? await generateDeviceKeys(user.id, prefix);
  let { encryptionPrivateKey, signingPrivateKey, identityKey } = material;

  const storedDeviceId = await loadValue<string>(`${prefix}:id`);
  const devices = await api.getDevices();
  let matching = devices.find((device) => device.id === storedDeviceId)
    || devices.find((device) => device.identityKey === identityKey);
  // A persisted id that disappeared from the active-device list was revoked.
  // Never resurrect its long-term identity by registering the same key again.
  if (storedDeviceId && !matching) {
    material = await generateDeviceKeys(user.id, prefix);
    ({ encryptionPrivateKey, signingPrivateKey, identityKey } = material);
    matching = undefined;
  }
  let device;
  if (matching) {
    const challenge = await api.getDeviceChallenge();
    const proof = await signDeviceChallenge(user.id, challenge.challenge, signingPrivateKey);
    device = await api.bindDevice(matching.id, challenge.challenge, proof);
  } else {

    try {
      const challenge = await api.getDeviceChallenge();
      const proof = await signDeviceChallenge(user.id, challenge.challenge, signingPrivateKey);
      device = await api.registerDevice(
        browserDeviceName(),
        identityKey,
        challenge.challenge,
        proof,
        stepUpPassword,
      );
    } catch (error) {
      if (!isRevokedIdentityRegistrationError(error)) throw error;
      // A missing local :id can leave a revoked keypair behind. Rotate the
      // complete identity atomically before one bounded registration retry;
      // never retry the rejected identity and never loop on a second 409.
      material = await generateDeviceKeys(user.id, prefix);
      ({ encryptionPrivateKey, signingPrivateKey, identityKey } = material);
      const challenge = await api.getDeviceChallenge();
      const proof = await signDeviceChallenge(user.id, challenge.challenge, signingPrivateKey);
      device = await api.registerDevice(
        browserDeviceName(),
        identityKey,
        challenge.challenge,
        proof,
        stepUpPassword,
      );
    }
  }
  const expectedIdentity = JSON.parse(identityKey) as DevicePublicBundle;
  const returnedIdentity = JSON.parse(device.identityKey) as DevicePublicBundle;
  if (expectedIdentity.signingKey.x !== returnedIdentity.signingKey.x || expectedIdentity.signingKey.y !== returnedIdentity.signingKey.y
    || expectedIdentity.encryptionKey.n !== returnedIdentity.encryptionKey.n || expectedIdentity.encryptionKey.e !== returnedIdentity.encryptionKey.e) throw new Error('DIRECTORY_INVALID');
  identityKey = device.identityKey;
  await saveValue(`${prefix}:identity`, identityKey);
  await saveValue(`${prefix}:id`, device.id);
  if (generation !== deviceSessionGeneration) throw new Error('AUTHENTICATION_CHANGED');
  activeDevice = {
    approved: device.approvedAt !== null,
    userId: user.id,
    deviceId: device.id,
    identityKey,
    encryptionPrivateKey,
    signingPrivateKey,
  };
  const directory = await verifiedDirectory(user.id);
  if (generation !== deviceSessionGeneration) throw new Error('AUTHENTICATION_CHANGED');
  const own = directory.devices[device.id];
  if (!own || own.identityKey !== identityKey || own.revoked) throw new Error('DIRECTORY_INVALID');
  activeDevice.approved = own.approved;
  return activeDevice;
}

async function signDeviceChallenge(userId: string, challenge: string, signingPrivateKey: CryptoKey): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPrivateKey,
    new TextEncoder().encode(serializeDeviceChallengeProof(userId, challenge)),
  );
  return arrayBufferToBase64(signature);
}

export function clearActiveDevice(): void {
  cancelGroupMaintenance();
  deviceSessionGeneration += 1;
  deviceInitializations.clear();
  channelKeyScopes.reset();
  channelKeyDeletionQueues.clear();
  activeDevice = null;
}

export function getActiveDevice(): ActiveDevice {
  if (!activeDevice) throw new Error('Security device is not initialized');
  return activeDevice;
}

export function isRevokedIdentityRegistrationError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && error.code === 'IDENTITY_REVOKED';
}

async function generateDeviceKeys(userId: string, prefix: string): Promise<DeviceKeyMaterial> {
  const desktop = Boolean(getDesktopBridge());
  const encryption = await crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, desktop, ['encrypt', 'decrypt']);
  const signing = await crypto.subtle.generateKey({
    name: 'ECDSA',
    namedCurve: 'P-256',
  }, desktop, ['sign', 'verify']);

  const encryptionKey = await crypto.subtle.exportKey('jwk', encryption.publicKey);
  const signingKey = await crypto.subtle.exportKey('jwk', signing.publicKey);
  encryptionKey.alg = 'RSA-OAEP-256';
  signingKey.alg = 'ES256';
  const bundle: DevicePublicBundle = { version: 1, encryptionKey, signingKey };
  const identityKey = JSON.stringify(bundle);
  if (!desktop) {
    await saveValues([
      [`${prefix}:encryption-private`, encryption.privateKey],
      [`${prefix}:signing-private`, signing.privateKey],
      [`${prefix}:identity`, identityKey],
    ]);
    return { encryptionPrivateKey: encryption.privateKey, signingPrivateKey: signing.privateKey, identityKey };
  }

  const encryptionPrivateKey = await crypto.subtle.exportKey('jwk', encryption.privateKey);
  const signingPrivateKey = await crypto.subtle.exportKey('jwk', signing.privateKey);
  encryptionPrivateKey.alg = 'RSA-OAEP-256';
  signingPrivateKey.alg = 'ES256';
  const stored: DesktopDevicePrivateBundle = {
    version: 1,
    identityKey,
    encryptionPrivateKey,
    signingPrivateKey,
  };
  if (!await setDesktopSecret(`device:${userId}`, JSON.stringify(stored))) {
    throw new Error('SECURE_DEVICE_STORAGE_UNAVAILABLE');
  }
  await saveValue(`${prefix}:identity`, identityKey);
  await Promise.all([
    deleteValue(`${prefix}:encryption-private`),
    deleteValue(`${prefix}:signing-private`),
  ]);
  return importDesktopDeviceKeys(stored);
}

async function loadDeviceKeyMaterial(userId: string, prefix: string): Promise<DeviceKeyMaterial | null> {
  if (!getDesktopBridge()) {
    const [encryptionPrivateKey, signingPrivateKey, identityKey] = await Promise.all([
      loadValue<CryptoKey>(`${prefix}:encryption-private`),
      loadValue<CryptoKey>(`${prefix}:signing-private`),
      loadValue<string>(`${prefix}:identity`),
    ]);
    return encryptionPrivateKey instanceof CryptoKey && signingPrivateKey instanceof CryptoKey && identityKey
      ? { encryptionPrivateKey, signingPrivateKey, identityKey }
      : null;
  }

  const encoded = await getDesktopSecret(`device:${userId}`);
  if (encoded === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(encoded);
  } catch {
    throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  }
  const material = await importDesktopDeviceKeys(parsed);
  await saveValue(`${prefix}:identity`, material.identityKey);
  await Promise.all([
    deleteValue(`${prefix}:encryption-private`),
    deleteValue(`${prefix}:signing-private`),
  ]);
  return material;
}

async function importDesktopDeviceKeys(value: unknown): Promise<DeviceKeyMaterial> {
  if (!value || typeof value !== 'object') throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  const candidate = value as Partial<DesktopDevicePrivateBundle>;
  if (
    candidate.version !== 1
    || typeof candidate.identityKey !== 'string'
    || !candidate.encryptionPrivateKey
    || !candidate.signingPrivateKey
    || candidate.encryptionPrivateKey.kty !== 'RSA'
    || candidate.encryptionPrivateKey.alg !== 'RSA-OAEP-256'
    || candidate.signingPrivateKey.kty !== 'EC'
    || candidate.signingPrivateKey.crv !== 'P-256'
    || candidate.signingPrivateKey.alg !== 'ES256'
  ) throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  let publicBundle: DevicePublicBundle;
  try {
    publicBundle = JSON.parse(candidate.identityKey) as DevicePublicBundle;
  } catch {
    throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  }
  if (
    publicBundle.version !== 1
    || publicBundle.encryptionKey.kty !== 'RSA'
    || publicBundle.encryptionKey.n !== candidate.encryptionPrivateKey.n
    || publicBundle.encryptionKey.e !== candidate.encryptionPrivateKey.e
    || publicBundle.signingKey.kty !== 'EC'
    || publicBundle.signingKey.crv !== 'P-256'
    || publicBundle.signingKey.x !== candidate.signingPrivateKey.x
    || publicBundle.signingKey.y !== candidate.signingPrivateKey.y
  ) throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  try {
    const [encryptionPrivateKey, signingPrivateKey] = await Promise.all([
      crypto.subtle.importKey(
        'jwk',
        candidate.encryptionPrivateKey,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt'],
      ),
      crypto.subtle.importKey(
        'jwk',
        candidate.signingPrivateKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign'],
      ),
    ]);
    return { encryptionPrivateKey, signingPrivateKey, identityKey: candidate.identityKey };
  } catch {
    throw new Error('SECURE_DEVICE_STORAGE_INVALID');
  }
}

/**
 * The key of the channel's current version. `write` (the default) commits
 * due removals and refreshes first and refuses while this device knows a
 * member to be revoked; `read` only brings the group up to date.
 */
export async function ensureChannelKey(
  channelId: string,
  options: { purpose?: ChannelKeyPurpose } = {},
): Promise<ChannelKey> {
  const scope = channelKeyScopes.capture(channelId);
  const purpose = options.purpose ?? 'write';
  return navigator.locks.request(
    `alparts-channel-key:${getActiveDevice().deviceId}:${channelId}`,
    () => currentChannelKey(channelId, scope, purpose),
  );
}

function currentChannelKey(channelId: string, scope: ChannelKeyScopeToken, purpose: ChannelKeyPurpose): Promise<ChannelKey> {
  return ensureChannelGroupKey(channelId, scope, {
    purpose,
    loadKey: (version) => loadGroupVersionKey(channelId, version, scope),
  });
}

/**
 * Whether this device holds the key of any version of the channel, derived
 * or delivered here (each has its key commitment) or restored from the
 * account's history backup. Such a device can show earlier messages while
 * it waits to be added to the channel's current group.
 */
export async function hasChannelHistoryKeys(channelId: string): Promise<boolean> {
  const device = getActiveDevice();
  for (const prefix of [`key-commitment:${channelId}:`, `recovered:${channelId}:`]) {
    if ((await listSecurityStateNames(device, prefix, 1)).length > 0) return true;
  }
  return false;
}

/**
 * Start the channel again from a new group (fresh start, identity
 * confirmation required). Earlier ciphertext stays untouched; devices that
 * cannot read it now never will. Members join the new group as other
 * devices add them.
 */
export async function startChannelWithoutHistory(channelId: string): Promise<ChannelKey> {
  const scope = channelKeyScopes.capture(channelId);
  return navigator.locks.request(`alparts-channel-key:${getActiveDevice().deviceId}:${channelId}`, async () => {
    const state = await api.getKeyRecipients(channelId);
    channelKeyScopes.assertCurrent(scope);
    assertKeyRecipientState(channelId, state);
    await createChannelGroupVersion(channelId, state, scope, { freshStart: state.group !== null });
    channelKeyScopes.assertCurrent(scope);
    return currentChannelKey(channelId, scope, 'write');
  });
}

async function unwrapChannelKey(encryptedKey: string, device: ActiveDevice): Promise<Uint8Array> {
  const raw = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    device.encryptionPrivateKey,
    base64ToArrayBuffer(encryptedKey),
  );
  return new Uint8Array(raw);
}

export function orderChannelKeyDeliveries<T extends Pick<ChannelKeyDelivery, 'deliveryId'>>(
  deliveries: readonly T[],
): T[] {
  return [...deliveries].sort((left, right) => (
    left.deliveryId < right.deliveryId ? -1 : left.deliveryId > right.deliveryId ? 1 : 0
  ));
}

export async function tryChannelKeyDeliveries<T>(
  deliveries: readonly ChannelKeyDelivery[],
  attempt: (delivery: ChannelKeyDelivery) => Promise<T | null>,
): Promise<{ delivery: ChannelKeyDelivery; value: T } | null> {
  for (const delivery of orderChannelKeyDeliveries(deliveries)) {
    const value = await attempt(delivery);
    if (value !== null) return { delivery, value };
  }
  return null;
}

export function isDecryptableChannelKeyEpoch(status: ChannelKeyEpochStatus): boolean {
  return status === 'active' || status === 'retired';
}

async function loadChannelKeyDelivery(
  channelId: string,
  deliveries: readonly ChannelKeyDelivery[],
  device: ActiveDevice,
  scope: ChannelKeyScopeToken,
  shouldAcknowledge: (delivery: ChannelKeyDelivery) => boolean,
): Promise<LoadedChannelKeyDelivery | null> {
  if (deliveries.length === 0) return null;
  await assertDeliveriesMatchDirectory(channelId, deliveries);
  const attempted = await tryChannelKeyDeliveries(deliveries, async (delivery) => {
    const storageId = channelStorageId(device, channelId, delivery.version);
    const stored = await loadPersistedChannelKey(storageId);
    channelKeyScopes.assertCurrent(scope);
    if (stored instanceof CryptoKey && delivery.confirmedAt && !mlsLocator(delivery.encryptedKey)) {
      // The cached key is reused only for the commitment it was verified against.
      const storedCommitment = await readSecurityState<string>(device, keyCommitmentStateName(channelId, delivery.version));
      channelKeyScopes.assertCurrent(scope);
      if (storedCommitment === delivery.keyCommitment) return { key: stored, acknowledged: false };
    }

    // Every unconfirmed immutable candidate is checked independently. A
    // malicious first writer therefore cannot prevent a later honest delivery.
    const raw = await unwrapCommittedChannelKey(channelId, delivery, device);
    if (!raw) return null;
    try {
      const key = await importChannelKey(raw);
      await saveChannelKeyForScope(storageId, key, scope, raw);
      await writeSecurityState(device, keyCommitmentStateName(channelId, delivery.version), delivery.keyCommitment, scope);
      let acknowledged = false;
      if (!delivery.confirmedAt && shouldAcknowledge(delivery)) {
        await acknowledgeCommittedChannelKey(channelId, delivery, device);
        channelKeyScopes.assertCurrent(scope);
        acknowledged = true;
      }
      if (delivery.confirmedAt || acknowledged) {
        try { await (await import('./recovery.service')).backupRawHistoryKey(channelId, delivery.version, raw); }
        catch { await writeSecurityState(device, `recovery-backup-pending:${channelId}:${delivery.version}`, true, scope); }
      }
      return { key, acknowledged };
    } finally {
      raw.fill(0);
    }
  });
  if (!attempted) return null;
  return { ...attempted.value, delivery: attempted.delivery };
}

function keyCommitmentStateName(channelId: string, version: number): string {
  return `key-commitment:${channelId}:${version}`;
}

/**
 * Distributor identities come from the server with each delivery. Bind them to
 * the verified channel directory before any wrap signature is trusted.
 */
async function assertDeliveriesMatchDirectory(channelId: string, deliveries: readonly ChannelKeyDelivery[]): Promise<void> {
  const ids = [...new Set(deliveries.map((d) => d.distributorDeviceId))];
  for (let i = 0; i < ids.length; i += 64) {
    const batch = ids.slice(i, i + 64);
    const directory = await api.getChannelDeviceDirectory(channelId, batch, 'active');
    for (const delivery of deliveries.filter((d) => batch.includes(d.distributorDeviceId))) {
      if (directory.find((d) => d.deviceId === delivery.distributorDeviceId)?.identityKey !== delivery.distributorIdentityKey) throw new Error('DIRECTORY_INVALID');
    }
  }
}

async function acknowledgeCommittedChannelKey(
  channelId: string,
  wrapped: ChannelKeyDelivery,
  device: ActiveDevice,
): Promise<void> {
  const signature = await signDevicePayload(serializeChannelKeyAcknowledgement({
    deliveryId: wrapped.deliveryId,
    channelId,
    keyVersion: wrapped.version,
    keyCommitment: wrapped.keyCommitment,
    recipientDeviceId: device.deviceId,
    distributorDeviceId: wrapped.distributorDeviceId,
    encryptedKey: wrapped.encryptedKey,
  }));
  await api.acknowledgeChannelKey(channelId, wrapped.deliveryId, signature);
}

const EQUIVOCATION_ERRORS = new Set(['INVALID_MLS_TRANSCRIPT', 'INVALID_MLS_SIGNATURE', 'DIRECTORY_INVALID', 'MLS_DOWNGRADE']);

async function unwrapCommittedChannelKey(
  channelId: string,
  wrapped: ChannelKeyDelivery,
  device: ActiveDevice,
): Promise<Uint8Array | null> {
  const envelope = {
    channelId,
    keyVersion: wrapped.version,
    keyCommitment: wrapped.keyCommitment,
    recipientDeviceId: device.deviceId,
    encryptedKey: wrapped.encryptedKey,
  };
  if (!await verifyDevicePayload(
    serializeChannelKeyWrap(envelope),
    wrapped.signature,
    wrapped.distributorIdentityKey,
  )) return null;
  let raw: Uint8Array;
  try {
    const locator = mlsLocator(wrapped.encryptedKey);
    if (locator && locator.version !== wrapped.version) return null;
    // From the first continuous group on, keys come only from that group:
    // never from a delivery, which a member and the server could forge.
    if (requiresGroupKey(wrapped.version, (await localGroupView(channelId)).v4Start)) {
      throw new Error('MLS_DOWNGRADE');
    }
    // A channel already on MLS never goes back to keys the server could
    // have produced itself.
    if (!locator && !nonMlsDeliveryAllowed(await pinnedMlsVersion(channelId), wrapped.version)) {
      throw new Error('MLS_DOWNGRADE');
    }
    raw = locator ? await deriveMlsDelivery(channelId, wrapped.version, locator.transcript, wrapped.epochStatus) : await unwrapChannelKey(wrapped.encryptedKey, device);
  } catch (error) {
    // A delivery that is simply not ours is skipped. Conflicting signed
    // history is evidence of server equivocation and must stay visible.
    if (error instanceof Error && EQUIVOCATION_ERRORS.has(error.message)) throw error;
    return null;
  }
  if (await computeKeyCommitment(raw) !== wrapped.keyCommitment) {
    raw.fill(0);
    return null;
  }
  return raw;
}

async function computeKeyCommitment(raw: Uint8Array): Promise<string> {
  // The view itself, not its buffer: an exporter result may share a larger buffer.
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw as Uint8Array<ArrayBuffer>));
  return arrayBufferToBase64(digest).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importChannelKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== 32) throw new Error('Invalid channel key length');
  return crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Persist what goes with a version key this device derived from a verified
 * group envelope (the key itself is in its `mls-key` record): the
 * commitment it was checked against, and the recovery backup (retried
 * later if it fails now).
 */
export async function storeGroupVersionKey(
  channelId: string,
  version: number,
  raw: Uint8Array,
  keyCommitment: string,
  scope: ChannelKeyScopeToken,
): Promise<void> {
  const device = getActiveDevice();
  if (raw.byteLength !== 32) throw new Error('Invalid channel key length');
  await writeSecurityState(device, keyCommitmentStateName(channelId, version), keyCommitment, scope);
  try {
    await (await import('./recovery.service')).backupRawHistoryKey(channelId, version, raw);
  } catch {
    await writeSecurityState(device, `recovery-backup-pending:${channelId}:${version}`, true, scope);
  }
}

/**
 * A version key this device derived from its own group, or null. It is
 * imported from the derived record itself, never from the per-version key
 * slot that a restored key also writes [sec-7].
 */
async function loadGroupVersionKey(
  channelId: string,
  version: number,
  scope: ChannelKeyScopeToken,
): Promise<CryptoKey | null> {
  const device = getActiveDevice();
  const archived = await readSecurityState<{ raw: string }>(device, `mls-key:${channelId}:${version}`);
  channelKeyScopes.assertCurrent(scope);
  if (!archived?.raw) return null;
  const raw = fromBase64(archived.raw);
  try {
    return await importChannelKey(raw);
  } finally {
    raw.fill(0);
  }
}

/**
 * A key restored from this account's history backup for a group version.
 * When this device verified that version itself, the commitments must agree.
 */
async function loadRecoveredGroupKey(
  channelId: string,
  version: number,
  scope: ChannelKeyScopeToken,
): Promise<CryptoKey | null> {
  const device = getActiveDevice();
  const recovered = await readSecurityState<{ raw: string }>(device, `recovered:${channelId}:${version}`);
  channelKeyScopes.assertCurrent(scope);
  if (!recovered?.raw) return null;
  const verified = await readSecurityState<string>(device, keyCommitmentStateName(channelId, version));
  channelKeyScopes.assertCurrent(scope);
  const raw = fromBase64(recovered.raw);
  try {
    if (verified && await computeKeyCommitment(raw) !== verified) return null;
    return await importChannelKey(raw);
  } finally {
    raw.fill(0);
  }
}

/**
 * From where keys must come from a continuous group: the lowest genesis this
 * device verified, or, while it waits to be added, the server's. Earlier
 * versions still use the per-device deliveries of before.
 */
async function groupKeyStart(channelId: string, scope: ChannelKeyScopeToken): Promise<number | null> {
  const local = (await localGroupView(channelId)).v4Start;
  channelKeyScopes.assertCurrent(scope);
  if (local !== null) return local;
  const state = await api.getKeyRecipients(channelId);
  channelKeyScopes.assertCurrent(scope);
  assertKeyRecipientState(channelId, state);
  return state.group?.genesisVersion ?? null;
}

export async function getChannelKeyForVersion(channelId: string, version: number): Promise<CryptoKey | null> {
  return (await getChannelKeysForVersions(channelId, [version])).get(version) ?? null;
}

/** Fetch at most one bounded API batch of historical channel-key versions. */
export async function getChannelKeysForVersions(
  channelId: string,
  requestedVersions: readonly number[],
  signal?: AbortSignal,
): Promise<Map<number, CryptoKey | null>> {
  throwIfRequestAborted(signal);
  const versions = [...new Set(requestedVersions)];
  if (
    versions.length < 1
    || versions.length > 64
    || versions.length !== requestedVersions.length
    || versions.some((version) => !Number.isSafeInteger(version) || version < 1 || version > 1_000_000)
  ) throw new Error('Invalid bounded channel key version request');
  const scope = channelKeyScopes.capture(channelId);
  const device = getActiveDevice();
  const local = await localGroupView(channelId);
  const legacyHead = await pinnedMlsVersion(channelId);
  channelKeyScopes.assertCurrent(scope);
  let groupStart = local.v4Start;
  const reached = Math.max(local.version ?? 0, legacyHead ?? 0);
  if (versions.some((version) => version > reached)) {
    // A version this device has not reached yet: catch up once. The server's
    // group start also counts while this device still waits to be added.
    const serverStart = await refreshGroupForHistory(channelId, scope);
    throwIfRequestAborted(signal);
    if (serverStart !== null) groupStart = groupStart === null ? serverStart : Math.min(groupStart, serverStart);
  }
  const loaded = new Map<number, CryptoKey | null>();
  const legacy: number[] = [];
  for (const version of versions) {
    if (!requiresGroupKey(version, groupStart)) {
      legacy.push(version);
      continue;
    }
    loaded.set(
      version,
      await loadGroupVersionKey(channelId, version, scope) ?? await loadRecoveredGroupKey(channelId, version, scope),
    );
  }
  if (legacy.length > 0) {
    // Versions before the first group: the earlier per-device deliveries.
    const response = await api.getChannelKeys(channelId, legacy, signal);
    throwIfRequestAborted(signal);
    channelKeyScopes.assertCurrent(scope);
    const requested = new Set(legacy);
    if (response.some((delivery) => !requested.has(delivery.version))) {
      throw new Error('Server returned a channel key outside the requested version set');
    }
    await Promise.all(legacy.map(async (version) => {
      const deliveries = response.filter((delivery) => (
        delivery.version === version && isDecryptableChannelKeyEpoch(delivery.epochStatus)
      ));
      const candidate = await loadChannelKeyDelivery(
        channelId,
        deliveries,
        device,
        scope,
        (delivery) => isDecryptableChannelKeyEpoch(delivery.epochStatus),
      );
      const recovered = await readSecurityState<{ raw: string }>(device, `recovered:${channelId}:${version}`);
      loaded.set(version, candidate?.key ?? (recovered ? await loadPersistedChannelKey(channelStorageId(device, channelId, version)) : null));
    }));
  }
  throwIfRequestAborted(signal);
  channelKeyScopes.assertCurrent(scope);
  return new Map(versions.map((version) => [version, loaded.get(version) ?? null]));
}

/**
 * Catch this device's group up for reading, and return where the server's
 * group starts. Waiting to be added is not an error here; contradicting
 * verified history is.
 */
async function refreshGroupForHistory(channelId: string, scope: ChannelKeyScopeToken): Promise<number | null> {
  const state = await api.getKeyRecipients(channelId);
  channelKeyScopes.assertCurrent(scope);
  assertKeyRecipientState(channelId, state);
  if (!state.group) return null;
  // Only a member catches up here; waiting to be added is ensureChannelKey's work.
  if (state.ownMembership && !state.ownMembership.rejoinRequested) {
    try {
      await syncChannelGroup(channelId, state, scope);
    } catch (error) {
      if (isGroupEquivocation(error)) throw error;
    }
  }
  channelKeyScopes.assertCurrent(scope);
  return state.group.genesisVersion;
}

function throwIfRequestAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error ? signal.reason : new Error('CHANNEL_KEY_REQUEST_ABORTED');
}

/** Best-effort local hygiene after this device loses channel access. */
export async function deletePersistedChannelKeys(channelId: string): Promise<void> {
  // Synchronous invalidation is deliberately first: any already-running key
  // fetch/import cannot return or persist after this point, even if its
  // network response wins the IndexedDB deletion race.
  channelKeyScopes.invalidate(channelId);
  const existing = channelKeyDeletionQueues.get(channelId);
  if (existing) return existing;
  const deletion = (async () => {
    const device = getActiveDevice();
    const prefix = buildChannelStoragePrefix(device.userId, device.deviceId, channelId);
    await deletePersistedChannelKeysForPrefix(prefix);
    await deleteChannelSecurityState(device, channelId);
  })();
  channelKeyDeletionQueues.set(channelId, deletion);
  try {
    await deletion;
  } finally {
    if (channelKeyDeletionQueues.get(channelId) === deletion) channelKeyDeletionQueues.delete(channelId);
  }
}

async function deletePersistedChannelKeysForPrefix(prefix: string): Promise<void> {
  const db = await getDb();
  return new Promise((resolve, reject) => {
    const desktopKeys: string[] = [];
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const request = tx.objectStore(STORE_NAME).openCursor(IDBKeyRange.bound(prefix, `${prefix}\uffff`));
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      if (isChannelStorageKeyForPrefix(cursor.key, prefix)) {
        if (getDesktopBridge()) desktopKeys.push(String(cursor.key));
        cursor.delete();
      }
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => {
      db.close();
      void Promise.all(desktopKeys.map((key) => deleteDesktopSecret(key))).then(() => resolve(), reject);
    };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

/** Restore only after a fresh authorized channel-list response includes it. */
export async function restoreChannelKeyScope(channelId: string): Promise<void> {
  // A fresh authorization response cannot race a still-running cursor delete;
  // otherwise that delete could remove a newly persisted authorized key.
  while (channelKeyDeletionQueues.has(channelId)) {
    await channelKeyDeletionQueues.get(channelId)!.catch(() => undefined);
  }
  channelKeyScopes.restore(channelId);
}

async function saveChannelKeyForScope(
  storageId: string,
  key: CryptoKey,
  scope: ChannelKeyScopeToken,
  raw?: Uint8Array,
): Promise<void> {
  channelKeyScopes.assertCurrent(scope);
  if (getDesktopBridge()) {
    if (!raw || raw.byteLength !== 32) throw new Error('SECURE_CHANNEL_STORAGE_INVALID');
    if (!await setDesktopSecret(storageId, arrayBufferToBase64(raw))) {
      throw new Error('SECURE_CHANNEL_STORAGE_UNAVAILABLE');
    }
    const pointer: DesktopSecretPointer = { version: 1, desktopSecret: true };
    await saveValue(storageId, pointer);
  } else {
    await saveValue(storageId, key);
  }
  if (channelKeyScopes.isCurrent(scope)) return;
  // A revocation can race the IDB transaction after its cursor already
  // passed this key. Remove the late write before rejecting the operation.
  await deletePersistedChannelKey(storageId).catch(() => undefined);
  channelKeyScopes.assertCurrent(scope);
}

async function loadPersistedChannelKey(storageId: string): Promise<CryptoKey | null> {
  const stored = await loadValue<CryptoKey | DesktopSecretPointer>(storageId);
  if (!getDesktopBridge()) return stored instanceof CryptoKey ? stored : null;
  if (!stored || stored instanceof CryptoKey || stored.version !== 1 || stored.desktopSecret !== true) return null;
  const encoded = await getDesktopSecret(storageId);
  if (encoded === null) {
    await deleteValue(storageId).catch(() => undefined);
    return null;
  }
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(base64ToArrayBuffer(encoded));
  } catch {
    throw new Error('SECURE_CHANNEL_STORAGE_INVALID');
  }
  if (raw.byteLength !== 32 || arrayBufferToBase64(raw) !== encoded) {
    raw.fill(0);
    throw new Error('SECURE_CHANNEL_STORAGE_INVALID');
  }
  try {
    return await importChannelKey(raw);
  } finally {
    raw.fill(0);
  }
}

async function deletePersistedChannelKey(storageId: string): Promise<void> {
  await deleteValue(storageId);
  if (getDesktopBridge()) await deleteDesktopSecret(storageId);
}

export function buildChannelStoragePrefix(userId: string, deviceId: string, channelId: string): string {
  if (![userId, deviceId, channelId].every(isUuid)) throw new Error('Channel key scope is invalid');
  return `channel:${userId}:${deviceId}:${channelId}:`;
}

export function isChannelStorageKeyForPrefix(key: IDBValidKey, prefix: string): boolean {
  if (typeof key !== 'string' || !key.startsWith(prefix)) return false;
  const version = key.slice(prefix.length);
  return /^[1-9]\d{0,6}$/.test(version) && Number(version) <= 1_000_000;
}

export async function encryptMessage(
  content: string,
  channelKey: CryptoKey,
  envelope: Omit<SignedMessageEnvelope, 'encryptedContent' | 'contentNonce'>,
) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: nonce,
    additionalData: new TextEncoder().encode(serializeMessageAad(envelope)),
    tagLength: 128,
  }, channelKey, padMessage(content));
  return { encrypted: arrayBufferToBase64(encrypted), nonce: arrayBufferToBase64(nonce) };
}

export async function decryptMessage(message: SignedMessageEnvelope, channelKey: CryptoKey): Promise<string> {
  const decrypted = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: base64ToArrayBuffer(message.contentNonce),
    additionalData: new TextEncoder().encode(serializeMessageAad(message)),
    tagLength: 128,
  }, channelKey, base64ToArrayBuffer(message.encryptedContent));
  return unpadMessage(new Uint8Array(decrypted));
}

export async function signMessageEnvelope(envelope: SignedMessageEnvelope): Promise<string> {
  return signDevicePayload(serializeMessageEnvelope(envelope));
}

export async function signAttachmentEnvelope(envelope: SignedAttachmentEnvelope): Promise<string> {
  return signDevicePayload(serializeAttachmentEnvelope(envelope));
}

export async function signVoiceSignalEnvelope(envelope: SignedVoiceSignalEnvelope): Promise<string> {
  return signDevicePayload(serializeVoiceSignalEnvelope(envelope));
}

export async function signVoiceKeyEnvelope(envelope: SignedVoiceKeyEnvelope): Promise<string> {
  return signDevicePayload(serializeVoiceKeyEnvelope(envelope));
}

export async function signDevicePayload(payload: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    getActiveDevice().signingPrivateKey,
    new TextEncoder().encode(payload),
  );
  return arrayBufferToBase64(signature);
}

export async function verifyMessageSignature(envelope: SignedMessageEnvelope, signature: string, identityKey: string): Promise<boolean> {
  return verifyDevicePayload(serializeMessageEnvelope(envelope), signature, identityKey);
}

export async function verifyAttachmentSignature(
  envelope: SignedAttachmentEnvelope,
  signature: string,
  identityKey: string,
): Promise<boolean> {
  return verifyDevicePayload(serializeAttachmentEnvelope(envelope), signature, identityKey);
}

export async function verifyVoiceSignalSignature(
  envelope: SignedVoiceSignalEnvelope,
  signature: string,
  identityKey: string,
): Promise<boolean> {
  return verifyDevicePayload(serializeVoiceSignalEnvelope(envelope), signature, identityKey);
}

export async function verifyVoiceKeySignature(
  envelope: SignedVoiceKeyEnvelope,
  signature: string,
  identityKey: string,
): Promise<boolean> {
  return verifyDevicePayload(serializeVoiceKeyEnvelope(envelope), signature, identityKey);
}

/** A call frame key encrypted to another device's directory bundle (RSA-OAEP-256). */
export async function wrapVoiceKey(key: Uint8Array, recipientIdentityKey: string): Promise<string> {
  const parsed = JSON.parse(recipientIdentityKey) as DevicePublicBundle;
  if (parsed.version !== 1 || parsed.encryptionKey?.kty !== 'RSA' || parsed.encryptionKey.alg !== 'RSA-OAEP-256') {
    throw new Error('Invalid device encryption key');
  }
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: parsed.encryptionKey.n, e: parsed.encryptionKey.e, alg: 'RSA-OAEP-256', ext: true },
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  return arrayBufferToBase64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, key as Uint8Array<ArrayBuffer>));
}

/** A call frame key encrypted to this device. */
export async function unwrapVoiceKey(wrappedKey: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    getActiveDevice().encryptionPrivateKey,
    base64ToArrayBuffer(wrappedKey),
  ));
}

export async function verifyDevicePayload(payload: string, signature: string, identityKey: string): Promise<boolean> {
  try {
    const parsed = JSON.parse(identityKey) as DevicePublicBundle;
    if (parsed.version !== 1 || parsed.signingKey.kty !== 'EC' || parsed.signingKey.crv !== 'P-256' || parsed.signingKey.alg !== 'ES256') {
      return false;
    }
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      parsed.signingKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      base64ToArrayBuffer(signature),
      new TextEncoder().encode(payload),
    );
  } catch {
    return false;
  }
}

function channelStorageId(device: ActiveDevice, channelId: string, version: number) {
  return `channel:${device.userId}:${device.deviceId}:${channelId}:${version}`;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function browserDeviceName(): string {
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  const platform = nav.userAgentData?.platform || navigator.platform || 'Web';
  return `${getDesktopBridge() ? 'Desktop' : 'Web'} (${platform.slice(0, 60)})`;
}

function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

/**
 * Keep a key restored from this account's history backup. A key this device
 * derived or verified itself is never replaced by a restored one [sec-7].
 */
export async function saveRecoveredChannelKey(channelId: string, version: number, raw: Uint8Array) {
  const scope = channelKeyScopes.capture(channelId);
  const device = getActiveDevice();
  const derived = await readSecurityState<{ raw: string }>(device, `mls-key:${channelId}:${version}`);
  const verified = await readSecurityState<string>(device, keyCommitmentStateName(channelId, version));
  channelKeyScopes.assertCurrent(scope);
  if (derived?.raw || (verified && verified !== await computeKeyCommitment(raw))) return;
  await saveChannelKeyForScope(channelStorageId(device, channelId, version), await importChannelKey(raw), scope, raw);
  await writeSecurityState(device, `recovered:${channelId}:${version}`, { raw: arrayBufferToBase64(raw) }, scope);
}

/**
 * The raw key of a version for this account's history backup. From the
 * first continuous group on, only a key whose commitment this device checked
 * against a signed envelope is backed up, never a delivery [sec-7].
 */
export async function exportHistoryKey(channelId: string, version: number): Promise<Uint8Array | null> {
  const scope = channelKeyScopes.capture(channelId);
  const device = getActiveDevice();
  const cached = await readSecurityState<{raw: string}>(device, `mls-key:${channelId}:${version}`);
  const recovered = await readSecurityState<{raw: string}>(device, `recovered:${channelId}:${version}`);
  channelKeyScopes.assertCurrent(scope);
  const local = (await localGroupView(channelId)).v4Start;
  channelKeyScopes.assertCurrent(scope);
  if (requiresGroupKey(version, local)) return verifiedGroupKey(channelId, version, [cached, recovered], scope);
  if (cached) return fromBase64(cached.raw);
  if (recovered?.raw) return fromBase64(recovered.raw);
  // While this device waits to be added, the server's group decides too.
  if (requiresGroupKey(version, await groupKeyStart(channelId, scope))) return null;
  const deliveries = (await api.getChannelKeys(channelId, [version]))
    .filter((delivery) => delivery.confirmedAt && isDecryptableChannelKeyEpoch(delivery.epochStatus));
  channelKeyScopes.assertCurrent(scope);
  if (deliveries.length === 0) return null;
  await assertDeliveriesMatchDirectory(channelId, deliveries);
  channelKeyScopes.assertCurrent(scope);
  for (const delivery of deliveries) {
    const raw = await unwrapCommittedChannelKey(channelId, delivery, device);
    channelKeyScopes.assertCurrent(scope);
    if (raw) return raw;
  }
  return null;
}

/** The first of `candidates` whose commitment matches the one this device verified for the version. */
async function verifiedGroupKey(
  channelId: string,
  version: number,
  candidates: ReadonlyArray<{ raw?: string } | null>,
  scope: ChannelKeyScopeToken,
): Promise<Uint8Array | null> {
  const verified = await readSecurityState<string>(getActiveDevice(), keyCommitmentStateName(channelId, version));
  channelKeyScopes.assertCurrent(scope);
  if (!verified) return null;
  for (const candidate of candidates) {
    if (!candidate?.raw) continue;
    const raw = fromBase64(candidate.raw);
    if (await computeKeyCommitment(raw) === verified) return raw;
    raw.fill(0);
  }
  return null;
}
