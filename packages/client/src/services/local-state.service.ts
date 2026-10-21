import { getActiveDevice } from './crypto.service';
import {
  MAX_OUTBOX_COMMANDS_PER_DEVICE,
  parseOutboxCommand,
  type OutboxCommand,
} from '../stores/outbox-model';
import { draftScopeChannelId } from '../stores/draft-scope';
import { getDesktopBridge, getDesktopSecret, setDesktopSecret } from './desktop.service';

const DB_NAME = 'alparts-local-state';
const DB_VERSION = 3;
const KEY_STORE = 'crypto';
const DRAFT_STORE = 'drafts';
const OUTBOX_STORE = 'outbox';
const DRAFT_OWNER_CHANNEL_INDEX = 'owner-channel';
const OUTBOX_OWNER_DEVICE_CREATED_INDEX = 'owner-device-created';
const OUTBOX_OWNER_CHANNEL_INDEX = 'owner-channel';
const OUTBOX_OWNER_DEVICE_CHANNEL_INDEX = 'owner-device-channel';
const FORMAT_VERSION = 1;

type RecordPurpose = 'draft' | 'outbox';

interface DeviceContext {
  userId: string;
  deviceId: string;
}

export type OutboxStorageContext = Readonly<DeviceContext>;

interface StoredLocalKey {
  version: 1;
  userId: string;
  deviceId: string;
  key: CryptoKey;
}

interface EncryptedRecord {
  id: string;
  version: 1;
  purpose: RecordPurpose;
  ownerId: string;
  deviceId: string;
  channelId: string;
  createdAt: string;
  updatedAt: string;
  nonce: string;
  ciphertext: string;
}

interface DraftPayload {
  version: 1;
  content: string;
}

const localKeyCache = new Map<string, CryptoKey>();
const localKeyInitializations = new Map<string, Promise<CryptoKey>>();
let localStateGeneration = 0;

function currentContext(): DeviceContext {
  const device = getActiveDevice();
  return { userId: device.userId, deviceId: device.deviceId };
}

/** Capture the authenticated device namespace once for an outbox operation. */
export function captureOutboxStorageContext(): OutboxStorageContext {
  return Object.freeze(currentContext());
}

/** Outbox plaintext may reach a send sink only while its captured principal is active. */
export function isOutboxStorageContextCurrent(context: OutboxStorageContext): boolean {
  try {
    const current = currentContext();
    return current.userId === context.userId && current.deviceId === context.deviceId;
  } catch {
    return false;
  }
}

function contextId(context: DeviceContext): string {
  return `${context.userId}:${context.deviceId}`;
}

function recordIdPrefix(context: DeviceContext): string {
  return `${context.userId}:${context.deviceId}:`;
}

function recordId(context: DeviceContext, scopeId: string): string {
  return `${recordIdPrefix(context)}${scopeId}`;
}

/** The scope an id names for this device, or null for an id in any other layout. */
function recordScopeId(context: DeviceContext, id: string): string | null {
  const prefix = recordIdPrefix(context);
  return id.startsWith(prefix) ? id.slice(prefix.length) : null;
}

/**
 * Before version 3 records were keyed `${ownerId}:${scopeId}`. Their
 * ciphertext is already bound to the device that saved them, so only the id
 * moves. A client that used the new layout at version 2 may have saved the
 * same scope again; the later write is kept.
 */
function moveLegacyRecordIds(store: IDBObjectStore): void {
  const request = store.openCursor();
  request.onsuccess = () => {
    const cursor = request.result;
    if (!cursor) return;
    const record = cursor.value as unknown;
    if (isEncryptedRecord(record)) {
      const owner = { userId: record.ownerId, deviceId: record.deviceId };
      const legacyPrefix = `${record.ownerId}:`;
      if (record.id.startsWith(legacyPrefix) && recordScopeId(owner, record.id) === null) {
        const moved: EncryptedRecord = { ...record, id: recordId(owner, record.id.slice(legacyPrefix.length)) };
        const existing = store.get(moved.id);
        existing.onsuccess = () => {
          const current = existing.result as unknown;
          if (!isEncryptedRecord(current) || current.updatedAt < moved.updatedAt) store.put(moved);
        };
        cursor.delete();
      }
    }
    cursor.continue();
  };
}

function openLocalDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
      const drafts = db.objectStoreNames.contains(DRAFT_STORE)
        ? request.transaction!.objectStore(DRAFT_STORE)
        : db.createObjectStore(DRAFT_STORE, { keyPath: 'id' });
      if (!drafts.indexNames.contains(DRAFT_OWNER_CHANNEL_INDEX)) {
        drafts.createIndex(
          DRAFT_OWNER_CHANNEL_INDEX,
          ['ownerId', 'channelId'],
          { unique: false },
        );
      }
      const outbox = db.objectStoreNames.contains(OUTBOX_STORE)
        ? request.transaction!.objectStore(OUTBOX_STORE)
        : db.createObjectStore(OUTBOX_STORE, { keyPath: 'id' });
      if (!outbox.indexNames.contains(OUTBOX_OWNER_DEVICE_CREATED_INDEX)) {
        outbox.createIndex(
          OUTBOX_OWNER_DEVICE_CREATED_INDEX,
          ['ownerId', 'deviceId', 'createdAt'],
          { unique: false },
        );
      }
      if (!outbox.indexNames.contains(OUTBOX_OWNER_CHANNEL_INDEX)) {
        outbox.createIndex(
          OUTBOX_OWNER_CHANNEL_INDEX,
          ['ownerId', 'channelId'],
          { unique: false },
        );
      }
      // Channel cleanup covers every device of the user, so the per-device
      // channel index of version 2 has no query left.
      if (outbox.indexNames.contains(OUTBOX_OWNER_DEVICE_CHANNEL_INDEX)) {
        outbox.deleteIndex(OUTBOX_OWNER_DEVICE_CHANNEL_INDEX);
      }
      if (event.oldVersion < 3) {
        moveLegacyRecordIds(drafts);
        moveLegacyRecordIds(outbox);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Local encrypted storage is blocked'));
  });
}

async function getRecord<T>(storeName: string, key: IDBValidKey): Promise<T | null> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).get(key);
    request.onsuccess = () => resolve((request.result as T | undefined) ?? null);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function getBoundedOutboxRecords(context: DeviceContext): Promise<unknown[]> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, 'readonly');
    const index = tx.objectStore(OUTBOX_STORE).index(OUTBOX_OWNER_DEVICE_CREATED_INDEX);
    const range = IDBKeyRange.bound(
      [context.userId, context.deviceId, ''],
      [context.userId, context.deviceId, '\uffff'],
    );
    const request = index.getAll(range, MAX_OUTBOX_COMMANDS_PER_DEVICE + 1);
    request.onsuccess = () => resolve((request.result as unknown[] | undefined) ?? []);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function putRecord(storeName: string, value: unknown, key?: IDBValidKey): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    if (key === undefined) store.put(value);
    else store.put(value, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function addRecord(storeName: string, value: unknown, key: IDBValidKey): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).add(value, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function deleteRecord(storeName: string, key: IDBValidKey): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function deleteRecordsByIndex(
  storeName: string,
  indexName: string,
  query: IDBKeyRange,
): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const index = tx.objectStore(storeName).index(indexName);
    const request = index.openCursor(query);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      cursor.delete();
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

async function putBoundedOutboxRecord(
  context: DeviceContext,
  command: OutboxCommand,
  encrypted: Pick<EncryptedRecord, 'nonce' | 'ciphertext'>,
): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, 'readwrite');
    const store = tx.objectStore(OUTBOX_STORE);
    const id = recordId(context, command.idempotencyKey);
    const existingRequest = store.get(id);
    const range = IDBKeyRange.bound(
      [context.userId, context.deviceId, ''],
      [context.userId, context.deviceId, '\uffff'],
    );
    const countRequest = store.index(OUTBOX_OWNER_DEVICE_CREATED_INDEX).count(range);
    let existingReady = false;
    let countReady = false;
    let failure: Error | null = null;
    let putStarted = false;

    const maybePut = () => {
      if (!existingReady || !countReady || putStarted) return;
      const existing = existingRequest.result as unknown;
      if (!existing && countRequest.result >= MAX_OUTBOX_COMMANDS_PER_DEVICE) {
        failure = new Error('OUTBOX_CAPACITY');
        tx.abort();
        return;
      }
      const now = new Date().toISOString();
      const record: EncryptedRecord = {
        id,
        version: FORMAT_VERSION,
        purpose: 'outbox',
        ownerId: context.userId,
        deviceId: context.deviceId,
        channelId: command.channelId,
        createdAt: isEncryptedRecord(existing) ? existing.createdAt : command.createdAt,
        updatedAt: now,
        ...encrypted,
      };
      putStarted = true;
      store.put(record);
    };
    existingRequest.onsuccess = () => { existingReady = true; maybePut(); };
    countRequest.onsuccess = () => { countReady = true; maybePut(); };
    existingRequest.onerror = () => { failure = existingRequest.error ?? new Error('Outbox lookup failed'); };
    countRequest.onerror = () => { failure = countRequest.error ?? new Error('Outbox count failed'); };
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(failure ?? tx.error); };
    tx.onabort = () => { db.close(); reject(failure ?? tx.error ?? new Error('Outbox write aborted')); };
  });
}

function isUsableLocalKey(record: StoredLocalKey | null, context: DeviceContext): record is StoredLocalKey {
  return Boolean(
    record
    && record.version === FORMAT_VERSION
    && record.userId === context.userId
    && record.deviceId === context.deviceId
    && typeof CryptoKey !== 'undefined'
    && record.key instanceof CryptoKey
    && record.key.type === 'secret'
    && record.key.algorithm.name === 'AES-GCM'
  );
}

export async function getLocalKey(context: DeviceContext): Promise<CryptoKey> {
  const id = contextId(context);
  const cached = localKeyCache.get(id);
  if (cached) return cached;
  const pending = localKeyInitializations.get(id);
  if (pending) return pending;

  const generation = localStateGeneration;
  let initialization: Promise<CryptoKey>;
  initialization = (async () => {
    if (getDesktopBridge()) {
      const secretName = `local:${context.userId}:${context.deviceId}`;
      let encoded = await getDesktopSecret(secretName);
      if (encoded === null) {
        const raw = crypto.getRandomValues(new Uint8Array(32));
        try {
          encoded = toBase64(raw);
          if (!await setDesktopSecret(secretName, encoded)) throw new Error('SECURE_LOCAL_STORAGE_UNAVAILABLE');
        } finally {
          raw.fill(0);
        }
      }
      let raw: Uint8Array;
      try {
        raw = new Uint8Array(fromBase64(encoded));
      } catch {
        throw new Error('SECURE_LOCAL_STORAGE_INVALID');
      }
      if (raw.byteLength !== 32 || toBase64(raw) !== encoded) {
        raw.fill(0);
        throw new Error('SECURE_LOCAL_STORAGE_INVALID');
      }
      try {
        const key = await crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        await deleteRecord(KEY_STORE, id).catch(() => undefined);
        if (generation === localStateGeneration) localKeyCache.set(id, key);
        return key;
      } finally {
        raw.fill(0);
      }
    }

    const stored = await getRecord<StoredLocalKey>(KEY_STORE, id);
    let key: CryptoKey;
    if (isUsableLocalKey(stored, context)) {
      key = stored.key;
    } else {
      const candidate = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      const value: StoredLocalKey = { version: FORMAT_VERSION, ...context, key: candidate };
      try {
        // `add` makes concurrent tabs converge on the first persisted key.
        await addRecord(KEY_STORE, value, id);
        key = candidate;
      } catch {
        const winner = await getRecord<StoredLocalKey>(KEY_STORE, id);
        if (isUsableLocalKey(winner, context)) key = winner.key;
        else {
          await putRecord(KEY_STORE, value, id);
          key = candidate;
        }
      }
    }
    if (generation === localStateGeneration) localKeyCache.set(id, key);
    return key;
  })().finally(() => {
    if (localKeyInitializations.get(id) === initialization) localKeyInitializations.delete(id);
  });
  localKeyInitializations.set(id, initialization);
  return initialization;
}

export function buildLocalStateAad(
  purpose: RecordPurpose,
  context: DeviceContext,
  scopeId: string,
): string {
  return JSON.stringify([FORMAT_VERSION, purpose, context.userId, context.deviceId, scopeId]);
}

async function encryptPayload(
  purpose: RecordPurpose,
  context: DeviceContext,
  scopeId: string,
  payload: unknown,
): Promise<Pick<EncryptedRecord, 'nonce' | 'ciphertext'>> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: nonce,
    additionalData: new TextEncoder().encode(buildLocalStateAad(purpose, context, scopeId)),
    tagLength: 128,
  }, await getLocalKey(context), new TextEncoder().encode(JSON.stringify(payload)));
  return { nonce: toBase64(nonce), ciphertext: toBase64(ciphertext) };
}

async function decryptPayload(
  record: EncryptedRecord,
  context: DeviceContext,
  scopeId: string,
): Promise<unknown> {
  if (
    record.version !== FORMAT_VERSION
    || record.ownerId !== context.userId
    || record.deviceId !== context.deviceId
  ) throw new Error('Encrypted local state belongs to an inactive device');
  const plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: fromBase64(record.nonce),
    additionalData: new TextEncoder().encode(buildLocalStateAad(record.purpose, context, scopeId)),
    tagLength: 128,
  }, await getLocalKey(context), fromBase64(record.ciphertext));
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
}

/** The record keeps its channel so revocation can find post drafts too. */
export async function saveLocalDraft(scopeId: string, content: string): Promise<void> {
  const context = currentContext();
  const encrypted = await encryptPayload('draft', context, scopeId, { version: FORMAT_VERSION, content });
  const existing = await getRecord<EncryptedRecord>(DRAFT_STORE, recordId(context, scopeId));
  const now = new Date().toISOString();
  const record: EncryptedRecord = {
    id: recordId(context, scopeId),
    version: FORMAT_VERSION,
    purpose: 'draft',
    ownerId: context.userId,
    deviceId: context.deviceId,
    channelId: draftScopeChannelId(scopeId),
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    ...encrypted,
  };
  await putRecord(DRAFT_STORE, record);
}

export async function loadLocalDraft(scopeId: string): Promise<string | null> {
  const context = currentContext();
  const id = recordId(context, scopeId);
  const value = await getRecord<unknown>(DRAFT_STORE, id);
  if (!value) return null;
  try {
    if (!isEncryptedRecord(value)) throw new Error('Invalid encrypted draft record');
    const record = value;
    if (record.purpose !== 'draft' || record.channelId !== draftScopeChannelId(scopeId)) throw new Error('Invalid draft metadata');
    const payload = await decryptPayload(record, context, scopeId) as Partial<DraftPayload>;
    if (payload.version !== FORMAT_VERSION || typeof payload.content !== 'string') throw new Error('Invalid draft payload');
    return payload.content;
  } catch {
    await deleteRecord(DRAFT_STORE, id).catch(() => undefined);
    return null;
  }
}

export async function deleteLocalDraft(scopeId: string): Promise<void> {
  const context = currentContext();
  await deleteRecord(DRAFT_STORE, recordId(context, scopeId));
}

/**
 * Remove the channel's draft and every post draft inside it. Access is lost
 * by the user, so drafts that earlier devices of the user left in this
 * profile go too.
 */
export async function deleteLocalDraftsForChannel(channelId: string): Promise<void> {
  const context = currentContext();
  await deleteRecordsByIndex(
    DRAFT_STORE,
    DRAFT_OWNER_CHANNEL_INDEX,
    IDBKeyRange.only([context.userId, channelId]),
  );
}

export async function saveOutboxCommand(
  context: OutboxStorageContext,
  command: OutboxCommand,
  isCurrent: () => boolean,
): Promise<void> {
  if (!isCurrent()) return;
  const encrypted = await encryptPayload('outbox', context, command.idempotencyKey, command);
  if (!isCurrent()) return;
  await putBoundedOutboxRecord(context, command, encrypted);
}

async function decryptOutboxRecord(record: EncryptedRecord, context: DeviceContext): Promise<OutboxCommand | null> {
  // The idempotency key is part of the AAD; guessing it from an id in another
  // layout would fail decryption and delete a record that may still be valid.
  const idempotencyKey = recordScopeId(context, record.id);
  if (idempotencyKey === null) return null;
  try {
    if (record.purpose !== 'outbox') throw new Error('Invalid outbox metadata');
    const command = parseOutboxCommand(await decryptPayload(record, context, idempotencyKey));
    if (
      !command
      || command.idempotencyKey !== idempotencyKey
      || command.channelId !== record.channelId
    ) throw new Error('Invalid outbox payload');
    return command;
  } catch {
    await deleteRecord(OUTBOX_STORE, record.id).catch(() => undefined);
    return null;
  }
}

export async function loadOutboxCommands(context: OutboxStorageContext): Promise<OutboxCommand[]> {
  const values = await getBoundedOutboxRecords(context);
  if (values.length > MAX_OUTBOX_COMMANDS_PER_DEVICE) throw new Error('OUTBOX_CAPACITY_REVIEW_REQUIRED');
  const owned: EncryptedRecord[] = [];
  for (const value of values) {
    if (isEncryptedRecord(value)) {
      if (value.ownerId === context.userId && value.deviceId === context.deviceId) owned.push(value);
      continue;
    }
    const possibleId = value && typeof value === 'object' && 'id' in value
      ? (value as { id?: unknown }).id
      : null;
    if (typeof possibleId === 'string' && possibleId.startsWith(`${context.userId}:`)) {
      await deleteRecord(OUTBOX_STORE, possibleId).catch(() => undefined);
    }
  }
  const commands = await Promise.all(owned.map((record) => decryptOutboxRecord(record, context)));
  return commands
    .filter((command): command is OutboxCommand => command !== null)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.idempotencyKey.localeCompare(right.idempotencyKey));
}

export async function loadOutboxCommand(
  context: OutboxStorageContext,
  idempotencyKey: string,
): Promise<OutboxCommand | null> {
  const id = recordId(context, idempotencyKey);
  const value = await getRecord<unknown>(OUTBOX_STORE, id);
  if (!value) return null;
  if (!isEncryptedRecord(value)) {
    await deleteRecord(OUTBOX_STORE, id).catch(() => undefined);
    return null;
  }
  return decryptOutboxRecord(value, context);
}

export async function deleteOutboxCommand(
  context: OutboxStorageContext,
  idempotencyKey: string,
): Promise<void> {
  await deleteRecord(OUTBOX_STORE, recordId(context, idempotencyKey));
}

/**
 * Remove the channel's queued messages. Access is lost by the user, so those
 * that earlier devices of the user left in this profile go too.
 */
export async function deleteOutboxCommandsForChannel(
  context: OutboxStorageContext,
  channelId: string,
): Promise<void> {
  await deleteRecordsByIndex(
    OUTBOX_STORE,
    OUTBOX_OWNER_CHANNEL_INDEX,
    IDBKeyRange.only([context.userId, channelId]),
  );
}

/** Drop all in-memory key references; encrypted records remain available to the same valid device. */
export function clearLocalStateSession(): void {
  localStateGeneration += 1;
  localKeyCache.clear();
  localKeyInitializations.clear();
}

function isEncryptedRecord(value: unknown): value is EncryptedRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<EncryptedRecord>;
  return record.version === FORMAT_VERSION
    && (record.purpose === 'draft' || record.purpose === 'outbox')
    && typeof record.id === 'string'
    && typeof record.ownerId === 'string'
    && typeof record.deviceId === 'string'
    && typeof record.channelId === 'string'
    && typeof record.createdAt === 'string'
    && typeof record.updatedAt === 'string'
    && typeof record.nonce === 'string'
    && typeof record.ciphertext === 'string';
}

function toBase64(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(value: string): ArrayBuffer {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}
