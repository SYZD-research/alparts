import { deleteChannelSecurityState, readSecurityState, writeSecurityState, fromBase64 } from './security-storage';
import { padMessage, unpadMessage } from './message-padding';
import { prepareMlsPackage, proposeMlsEpoch, deriveMlsDelivery, mlsLocator } from './mls.service';
import { verifyDirectoryDevices, verifiedDirectory } from './directory.service';
import {
  serializeAttachmentEnvelope,
  serializeDeviceChallengeProof,
  serializeChannelKeyAcknowledgement,
  serializeChannelKeyEpochAbort,
  serializeChannelKeyWrap,
  serializeMessageAad,
  serializeMessageEnvelope,
  serializeVoiceSignalEnvelope,
  type SignedAttachmentEnvelope,
  type SignedMessageEnvelope,
  type SignedVoiceSignalEnvelope,
  type User,
} from '@alparts/shared';
import {
  api,
  ApiError,
  type ChannelKeyDelivery,
  type ChannelKeyEpochStatus,
  type ChannelKeyRecipientState,
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

export const CHANNEL_KEY_ACTIVATION_PENDING = 'CHANNEL_KEY_ACTIVATION_PENDING';
export const CHANNEL_KEY_DELIVERY_PENDING = 'CHANNEL_KEY_DELIVERY_PENDING';

/**
 * The candidate key is valid, but the server cannot activate it until every
 * required recipient device has acknowledged its exact delivery. This is an
 * availability state, not evidence of a cryptographic failure.
 */
export class ChannelKeyActivationPendingError extends Error {
  readonly code = CHANNEL_KEY_ACTIVATION_PENDING;

  constructor(readonly remainingDeviceCount: number) {
    super(
      remainingDeviceCount > 0
        ? `会話の準備をしています（あと${remainingDeviceCount}台）。参加中の端末でこの会話を開いてください。`
        : '会話の準備をしています',
    );
    this.name = 'ChannelKeyActivationPendingError';
  }
}

export function isChannelKeyActivationPendingError(
  error: unknown,
): error is ChannelKeyActivationPendingError {
  return error instanceof ChannelKeyActivationPendingError
    || (typeof error === 'object'
      && error !== null
      && (error as { code?: unknown }).code === CHANNEL_KEY_ACTIVATION_PENDING);
}

/**
 * This device is authorized, but another already-authorized device must wrap
 * the existing channel key for it. Treat this as recoverable availability,
 * never as a cryptographic verification failure or a reason to use plaintext.
 */
export class ChannelKeyDeliveryPendingError extends Error {
  readonly code = CHANNEL_KEY_DELIVERY_PENDING;

  constructor() {
    super('A previously registered device must make this channel available to the current device');
    this.name = 'ChannelKeyDeliveryPendingError';
  }
}

export function isChannelKeyDeliveryPendingError(
  error: unknown,
): error is ChannelKeyDeliveryPendingError {
  return error instanceof ChannelKeyDeliveryPendingError
    || (typeof error === 'object'
      && error !== null
      && (error as { code?: unknown }).code === CHANNEL_KEY_DELIVERY_PENDING);
}

const MAX_KEY_RECONCILIATION_ATTEMPTS = 6;

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

export async function ensureChannelKey(channelId: string): Promise<ChannelKey> {
  const scope = channelKeyScopes.capture(channelId);
  return navigator.locks.request(`alparts-channel-key:${getActiveDevice().deviceId}:${channelId}`, () => ensureChannelKeyAttempt(channelId, scope));
}

/**
 * Explicitly establish a new writable epoch without requiring this endpoint
 * to possess the previous epoch. Historical ciphertext remains untouched and
 * unavailable here; every current endpoint still receives the new signed key.
 */
export async function startChannelWithoutHistory(channelId: string): Promise<ChannelKey> {
  const scope = channelKeyScopes.capture(channelId);
  return navigator.locks.request(`alparts-channel-key:${getActiveDevice().deviceId}:${channelId}`, async () => {
    const state = await api.getKeyRecipients(channelId);
    channelKeyScopes.assertCurrent(scope);
    assertKeyRecipientState(state);
    await proposeMlsEpoch(channelId, state, true);
    channelKeyScopes.assertCurrent(scope);
    return ensureChannelKeyAttempt(channelId, scope);
  });
}

async function ensureChannelKeyAttempt(
  channelId: string,
  scope: ChannelKeyScopeToken,
): Promise<ChannelKey> {
  const device = getActiveDevice();
  for (let attempt = 0; attempt < MAX_KEY_RECONCILIATION_ATTEMPTS; attempt += 1) {
    channelKeyScopes.assertCurrent(scope);
    const [state, deliveries] = await Promise.all([
      api.getKeyRecipients(channelId),
      api.getChannelKeys(channelId),
    ]);
    channelKeyScopes.assertCurrent(scope);
    assertKeyRecipientState(state);
    await verifyDirectoryDevices(channelId, state.recipients, true);
    if (state.pendingVersion === null && (state.rotationRequired || state.currentVersion === 0)) {
      try { await prepareMlsPackage(channelId, state.nextVersion); }
      catch (error) {
        if (error instanceof ApiError && error.status === 409) continue;
        throw error;
      }
    }

    const activeDeliveries = state.currentVersion === 0 ? [] : deliveriesForEpoch(
      deliveries,
      'active',
      state.currentVersion,
      state.keyCommitment!,
    );
    const active = await loadChannelKeyDelivery(
      channelId,
      activeDeliveries,
      device,
      scope,
      () => true,
    );
    channelKeyScopes.assertCurrent(scope);
    if (active?.acknowledged) continue;

    const hasPendingEpoch = state.pendingVersion !== null;
    const pendingDeliveries = !hasPendingEpoch ? [] : deliveriesForEpoch(
      deliveries,
      'pending',
      state.pendingVersion!,
      state.pendingKeyCommitment!,
    );
    const pending = await loadChannelKeyDelivery(
      channelId,
      pendingDeliveries,
      device,
      scope,
      () => true,
    );
    channelKeyScopes.assertCurrent(scope);
    if (pending?.acknowledged) continue;

    // GET requests are not one atomic snapshot. Retry an observed monotonic
    // pending -> active -> retired transition instead of misclassifying it as
    // an invalid delivery.
    if (
      (!active && hasAdjacentEpochStatus(deliveries, state.currentVersion, state.keyCommitment, 'active'))
      || (hasPendingEpoch && !pending && hasAdjacentEpochStatus(
        deliveries,
        state.pendingVersion!,
        state.pendingKeyCommitment!,
        'pending',
      ))
    ) continue;

    if (hasPendingEpoch) {
      if (state.pendingInvalid) {
        if (
          state.canAbortPending
          && state.recipients.some((recipient) => recipient.deviceId === device.deviceId)
          && hasActiveEpochAuthority(state, device.deviceId, Boolean(active))
        ) {
          await abortPendingChannelKeyEpoch(channelId, state, device);
          channelKeyScopes.assertCurrent(scope);
          await deletePersistedChannelKey(channelStorageId(device, channelId, state.pendingVersion!)).catch(() => undefined);
          continue;
        }
        throw new Error('Invalid pending channel key epoch requires an authorized manager to abort it');
      }
      if (!pending) {
        if (
          state.canAbortPending
          && state.recipients.some((recipient) => recipient.deviceId === device.deviceId)
          && hasActiveEpochAuthority(state, device.deviceId, Boolean(active))
        ) {
          await abortPendingChannelKeyEpoch(channelId, state, device);
          channelKeyScopes.assertCurrent(scope);
          await deletePersistedChannelKey(channelStorageId(device, channelId, state.pendingVersion!)).catch(() => undefined);
          continue;
        }
        if (pendingDeliveries.length === 0) throw new ChannelKeyDeliveryPendingError();
        throw new Error('This device has not received a valid pending channel key delivery');
      }

      if (!state.pendingAcknowledgedDeviceIds.includes(device.deviceId)) continue;
      const acknowledged = new Set(state.pendingAcknowledgedDeviceIds);
      const required = new Set(
        state.pendingRequiredDeviceIds
        ?? state.recipients.map((recipient) => recipient.deviceId),
      );
      const missing = state.recipients.filter((recipient) => (
        required.has(recipient.deviceId) && !acknowledged.has(recipient.deviceId)
      ));
      if (missing.length === 0) continue;
      if (mlsLocator(pending.delivery.encryptedKey)) throw new ChannelKeyActivationPendingError(missing.length);
      try {
        await distributeFromDelivery(channelId, pending.delivery, missing, device);
        channelKeyScopes.assertCurrent(scope);
      } catch (error) {
        channelKeyScopes.assertCurrent(scope);
        // The candidate key is immutable per distributor. A conflict means
        // this device already supplied its one repair candidate.
        if (!(error instanceof ApiError && error.status === 409)) throw error;
      }
      throw new ChannelKeyActivationPendingError(missing.length);
    }

    if (state.rotationRequired || state.currentVersion === 0) {
      if (!state.canRotate) {
        throw new ChannelKeyDeliveryPendingError();
      }
      if (!state.recipients.some((recipient) => recipient.deviceId === device.deviceId)) {
        throw new Error('Current device is not an authorized key recipient');
      }
      if (
        state.currentVersion > 0
        && !state.historyRecoveryRequired
        && (!active || !state.distributedDeviceIds.includes(device.deviceId))
      ) {
        throw new Error('Current device must accept the active channel key before rotating it');
      }

      try {
        await proposeMlsEpoch(channelId, state);
        channelKeyScopes.assertCurrent(scope);
        continue;
      } catch (error) {
        channelKeyScopes.assertCurrent(scope);
        if (error instanceof ApiError && error.status === 409) continue;
        throw error;
      }
    }

    if (!active || !state.distributedDeviceIds.includes(device.deviceId)) {
      if (!active && activeDeliveries.length === 0) throw new ChannelKeyDeliveryPendingError();
      throw new Error('This device has not received the active channel key; approve it from an existing device');
    }

    const distributed = new Set(state.distributedDeviceIds);
    const missing = state.recipients.filter((recipient) => !distributed.has(recipient.deviceId));
    if (missing.length > 0) {
      try {
        await distributeFromDelivery(channelId, active.delivery, missing, device);
        channelKeyScopes.assertCurrent(scope);
      } catch (error) {
        channelKeyScopes.assertCurrent(scope);
        if (!(error instanceof ApiError && error.status === 409)) throw error;
      }
    }
    channelKeyScopes.assertCurrent(scope);
    return { key: active.key, version: state.currentVersion };
  }

  throw new Error('Channel key state changed too many times; retry the operation');
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

/**
 * A device may administer a provisional epoch with no active key only when no
 * authorized non-revoked accepted holder remains. This never grants access to
 * historical ciphertext; it only permits fail-closed abort/recovery.
 */
export function hasActiveEpochAuthority(
  state: Pick<
    ChannelKeyRecipientState,
    'currentVersion' | 'historyRecoveryRequired' | 'distributedDeviceIds'
  >,
  deviceId: string,
  hasLoadedActiveKey: boolean,
): boolean {
  return state.currentVersion === 0
    || state.historyRecoveryRequired
    || (hasLoadedActiveKey && state.distributedDeviceIds.includes(deviceId));
}

function deliveriesForEpoch(
  deliveries: readonly ChannelKeyDelivery[],
  status: ChannelKeyEpochStatus,
  version: number,
  keyCommitment: string,
): ChannelKeyDelivery[] {
  return deliveries.filter((delivery) => (
    delivery.epochStatus === status
    && delivery.version === version
    && delivery.keyCommitment === keyCommitment
  ));
}

function hasAdjacentEpochStatus(
  deliveries: readonly ChannelKeyDelivery[],
  version: number,
  keyCommitment: string | null,
  expectedStatus: ChannelKeyEpochStatus,
): boolean {
  if (version === 0 || !keyCommitment) return false;
  return deliveries.some((delivery) => (
    delivery.version === version
    && delivery.keyCommitment === keyCommitment
    && delivery.epochStatus !== expectedStatus
  ));
}

// Mirrors the server bounds: 50 members with at most 8 active devices each.
const MAX_KEY_RECIPIENT_USERS = 50;
const MAX_KEY_RECIPIENTS = MAX_KEY_RECIPIENT_USERS * 8;

function assertKeyRecipientState(state: ChannelKeyRecipientState): void {
  if (
    !Array.isArray(state.recipients)
    || state.recipients.length > MAX_KEY_RECIPIENTS
    || new Set(state.recipients.map((recipient) => recipient.userId)).size > MAX_KEY_RECIPIENT_USERS
  ) {
    throw new Error('Server returned an unbounded channel key recipient set');
  }
  const recipientIds = new Set(state.recipients.map((recipient) => recipient.deviceId));
  if (recipientIds.size !== state.recipients.length) {
    throw new Error('Server returned duplicate channel key recipients');
  }
  if (
    typeof state.pendingInvalid !== 'boolean'
    || typeof state.historyRecoveryRequired !== 'boolean'
  ) {
    throw new Error('Server returned an invalid pending channel key state');
  }
  if ((state.currentVersion === 0) !== (state.keyCommitment === null)) {
    throw new Error('Server returned an invalid active channel key state');
  }
  if ((state.pendingVersion === null) !== (state.pendingKeyCommitment === null)) {
    throw new Error('Server returned an invalid pending channel key state');
  }
  if (
    state.historyRecoveryRequired
    && (state.currentVersion === 0 || !state.rotationRequired)
  ) {
    throw new Error('Server returned an invalid channel key recovery state');
  }
  if (state.nextVersion <= state.currentVersion || (state.pendingVersion !== null && state.nextVersion <= state.pendingVersion)) {
    throw new Error('Server returned a non-monotonic channel key version');
  }
  if (
    new Set(state.pendingAcknowledgedDeviceIds).size !== state.pendingAcknowledgedDeviceIds.length
    || state.pendingAcknowledgedDeviceIds.some((deviceId) => !recipientIds.has(deviceId))
    || (state.pendingVersion === null && state.pendingAcknowledgedDeviceIds.length > 0)
  ) {
    throw new Error('Server returned an invalid pending channel key acknowledgement state');
  }
  if (state.pendingRequiredDeviceIds !== undefined && (
    new Set(state.pendingRequiredDeviceIds).size !== state.pendingRequiredDeviceIds.length
    || state.pendingRequiredDeviceIds.some((deviceId) => !recipientIds.has(deviceId))
    || (state.pendingVersion === null && state.pendingRequiredDeviceIds.length > 0)
    || (state.pendingVersion !== null && state.pendingRequiredDeviceIds.length === 0)
  )) {
    throw new Error('Server returned an invalid pending channel key requirement state');
  }
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
    const directory = await api.getChannelDeviceDirectory(channelId, batch);
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

const EQUIVOCATION_ERRORS = new Set(['INVALID_MLS_TRANSCRIPT', 'INVALID_MLS_SIGNATURE', 'DIRECTORY_INVALID']);

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

async function distributeFromDelivery(
  channelId: string,
  delivery: ChannelKeyDelivery,
  recipients: Array<{ deviceId: string; identityKey: string }>,
  device: ActiveDevice,
): Promise<void> {
  const raw = await unwrapCommittedChannelKey(channelId, delivery, device);
  if (!raw) throw new Error('Channel key commitment verification failed');
  try {
    const keys = await wrapForRecipients(raw, recipients, {
      channelId,
      version: delivery.version,
      keyCommitment: delivery.keyCommitment,
    });
    await api.distributeChannelKeys(channelId, delivery.version, delivery.keyCommitment, keys);
  } finally {
    raw.fill(0);
  }
}

async function abortPendingChannelKeyEpoch(
  channelId: string,
  state: ChannelKeyRecipientState,
  device: ActiveDevice,
): Promise<void> {
  if (state.pendingVersion === null || state.pendingKeyCommitment === null) {
    throw new Error('There is no pending channel key epoch to abort');
  }
  const signature = await signDevicePayload(serializeChannelKeyEpochAbort({
    channelId,
    keyVersion: state.pendingVersion,
    keyCommitment: state.pendingKeyCommitment,
    deviceId: device.deviceId,
  }));
  await api.abortChannelKeyEpoch(
    channelId,
    state.pendingVersion,
    state.pendingKeyCommitment,
    signature,
  );
}

async function computeKeyCommitment(raw: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw.buffer as ArrayBuffer));
  return arrayBufferToBase64(digest).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importChannelKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function wrapForRecipients(
  raw: Uint8Array,
  recipients: Array<{ deviceId: string; identityKey: string }>,
  context: { channelId: string; version: number; keyCommitment: string },
): Promise<Array<{ deviceId: string; encryptedKey: string; signature: string }>> {
  return Promise.all(recipients.map(async (recipient) => {
    const encryptedKey = await wrapChannelKey(raw, recipient.identityKey);
    const signature = await signDevicePayload(serializeChannelKeyWrap({
      channelId: context.channelId,
      keyVersion: context.version,
      keyCommitment: context.keyCommitment,
      recipientDeviceId: recipient.deviceId,
      encryptedKey,
    }));
    return { deviceId: recipient.deviceId, encryptedKey, signature };
  }));
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
  const response = await api.getChannelKeys(channelId, versions, signal);
  throwIfRequestAborted(signal);
  channelKeyScopes.assertCurrent(scope);
  const requested = new Set(versions);
  if (response.some((delivery) => !requested.has(delivery.version))) {
    throw new Error('Server returned a channel key outside the requested version set');
  }
  const loaded = await Promise.all(versions.map(async (version) => {
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
    return [version, candidate?.key ?? (recovered ? await loadPersistedChannelKey(channelStorageId(device, channelId, version)) : null)] as const;
  }));
  throwIfRequestAborted(signal);
  channelKeyScopes.assertCurrent(scope);
  return new Map(loaded);
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

async function wrapChannelKey(raw: Uint8Array, identityKey: string): Promise<string> {
  const parsed = JSON.parse(identityKey) as DevicePublicBundle;
  if (parsed.version !== 1 || parsed.encryptionKey.kty !== 'RSA' || parsed.encryptionKey.alg !== 'RSA-OAEP-256') {
    throw new Error('Invalid recipient identity key');
  }
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    parsed.encryptionKey,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  return arrayBufferToBase64(await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    raw.buffer as ArrayBuffer,
  ));
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

export async function saveRecoveredChannelKey(channelId: string, version: number, raw: Uint8Array) {
  const scope = channelKeyScopes.capture(channelId);
  const device = getActiveDevice();
  await saveChannelKeyForScope(channelStorageId(device, channelId, version), await importChannelKey(raw), scope, raw);
  await writeSecurityState(device, `recovered:${channelId}:${version}`, { raw: arrayBufferToBase64(raw) }, scope);
}
export async function exportHistoryKey(channelId: string, version: number): Promise<Uint8Array | null> {
  const scope = channelKeyScopes.capture(channelId);
  const device = getActiveDevice();
  const cached = await readSecurityState<{raw: string}>(device, `mls-key:${channelId}:${version}`);
  channelKeyScopes.assertCurrent(scope);
  if (cached) return fromBase64(cached.raw);
  const recovered = await readSecurityState<{raw: string}>(device, `recovered:${channelId}:${version}`);
  channelKeyScopes.assertCurrent(scope);
  if (recovered?.raw) return fromBase64(recovered.raw);
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
