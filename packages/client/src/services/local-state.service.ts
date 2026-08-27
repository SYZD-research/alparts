import { getActiveDevice } from './crypto.service';
import { parseOutboxCommand, type OutboxCommand } from '../stores/outbox-model';

const DB_NAME = 'alparts-local-state';
const DB_VERSION = 1;
const KEY_STORE = 'crypto';
const DRAFT_STORE = 'drafts';
const OUTBOX_STORE = 'outbox';
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

function recordId(ownerId: string, scopeId: string): string {
  return `${ownerId}:${scopeId}`;
}

function openLocalDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
      if (!db.objectStoreNames.contains(DRAFT_STORE)) db.createObjectStore(DRAFT_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(OUTBOX_STORE)) db.createObjectStore(OUTBOX_STORE, { keyPath: 'id' });
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

async function getAllRecords<T>(storeName: string): Promise<T[]> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).getAll();
    request.onsuccess = () => resolve((request.result as T[] | undefined) ?? []);
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

async function deleteRecordsMatching(
  storeName: string,
  predicate: (value: unknown) => boolean,
): Promise<void> {
  const db = await openLocalDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const request = tx.objectStore(storeName).openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      if (predicate(cursor.value)) cursor.delete();
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
    tx.onabort = () => { db.close(); reject(tx.error); };
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

async function getLocalKey(context: DeviceContext): Promise<CryptoKey> {
  const id = contextId(context);
  const cached = localKeyCache.get(id);
  if (cached) return cached;
  const pending = localKeyInitializations.get(id);
  if (pending) return pending;

  const generation = localStateGeneration;
  let initialization: Promise<CryptoKey>;
  initialization = (async () => {
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

export async function saveLocalDraft(channelId: string, content: string): Promise<void> {
  const context = currentContext();
  const encrypted = await encryptPayload('draft', context, channelId, { version: FORMAT_VERSION, content });
  const existing = await getRecord<EncryptedRecord>(DRAFT_STORE, recordId(context.userId, channelId));
  const now = new Date().toISOString();
  const record: EncryptedRecord = {
    id: recordId(context.userId, channelId),
    version: FORMAT_VERSION,
    purpose: 'draft',
    ownerId: context.userId,
    deviceId: context.deviceId,
    channelId,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    ...encrypted,
  };
  await putRecord(DRAFT_STORE, record);
}

export async function loadLocalDraft(channelId: string): Promise<string | null> {
  const context = currentContext();
  const id = recordId(context.userId, channelId);
  const value = await getRecord<unknown>(DRAFT_STORE, id);
  if (!value) return null;
  try {
    if (!isEncryptedRecord(value)) throw new Error('Invalid encrypted draft record');
    const record = value;
    if (record.purpose !== 'draft' || record.channelId !== channelId) throw new Error('Invalid draft metadata');
    const payload = await decryptPayload(record, context, channelId) as Partial<DraftPayload>;
    if (payload.version !== FORMAT_VERSION || typeof payload.content !== 'string') throw new Error('Invalid draft payload');
    return payload.content;
  } catch {
    await deleteRecord(DRAFT_STORE, id).catch(() => undefined);
    return null;
  }
}

export async function deleteLocalDraft(channelId: string): Promise<void> {
  const context = currentContext();
  await deleteRecord(DRAFT_STORE, recordId(context.userId, channelId));
}

export async function saveOutboxCommand(
  context: OutboxStorageContext,
  command: OutboxCommand,
  isCurrent: () => boolean,
): Promise<void> {
  if (!isCurrent()) return;
  const encrypted = await encryptPayload('outbox', context, command.idempotencyKey, command);
  if (!isCurrent()) return;
  const id = recordId(context.userId, command.idempotencyKey);
  const existing = await getRecord<EncryptedRecord>(OUTBOX_STORE, id);
  if (!isCurrent()) return;
  const now = new Date().toISOString();
  const record: EncryptedRecord = {
    id,
    version: FORMAT_VERSION,
    purpose: 'outbox',
    ownerId: context.userId,
    deviceId: context.deviceId,
    channelId: command.channelId,
    createdAt: existing?.createdAt || command.createdAt,
    updatedAt: now,
    ...encrypted,
  };
  if (!isCurrent()) return;
  await putRecord(OUTBOX_STORE, record);
}

async function decryptOutboxRecord(record: EncryptedRecord, context: DeviceContext): Promise<OutboxCommand | null> {
  try {
    if (record.purpose !== 'outbox') throw new Error('Invalid outbox metadata');
    const command = parseOutboxCommand(await decryptPayload(record, context, record.id.slice(record.ownerId.length + 1)));
    if (
      !command
      || command.idempotencyKey !== record.id.slice(record.ownerId.length + 1)
      || command.channelId !== record.channelId
    ) throw new Error('Invalid outbox payload');
    return command;
  } catch {
    await deleteRecord(OUTBOX_STORE, record.id).catch(() => undefined);
    return null;
  }
}

export async function loadOutboxCommands(context: OutboxStorageContext): Promise<OutboxCommand[]> {
  const values = await getAllRecords<unknown>(OUTBOX_STORE);
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
  const id = recordId(context.userId, idempotencyKey);
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
  await deleteRecord(OUTBOX_STORE, recordId(context.userId, idempotencyKey));
}

export async function deleteOutboxCommandsForChannel(
  context: OutboxStorageContext,
  channelId: string,
): Promise<void> {
  await deleteRecordsMatching(OUTBOX_STORE, (value) => (
    isEncryptedRecord(value)
    && value.purpose === 'outbox'
    && value.ownerId === context.userId
    && value.deviceId === context.deviceId
    && value.channelId === channelId
  ));
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
