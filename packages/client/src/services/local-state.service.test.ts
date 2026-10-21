import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Encrypted drafts and queued messages of each device: records saved before
// the device was part of their id still load after the upgrade and leave with
// a revoked channel, and devices of one user in one browser profile never
// overwrite or delete each other's records. IndexedDB is an in-memory
// stand-in that keeps database versions.

const device = vi.hoisted(() => ({ active: { userId: '', deviceId: '' } }));

vi.mock('./crypto.service', () => ({ getActiveDevice: () => device.active }));

vi.mock('./desktop.service', () => ({
  getDesktopBridge: () => null,
  getDesktopSecret: vi.fn(),
  setDesktopSecret: vi.fn(),
}));

import { draftScopeChannelId, forumPostDraftScope } from '../stores/draft-scope';
import { createOutboxCommand, MAX_OUTBOX_COMMANDS_PER_DEVICE, type OutboxCommand } from '../stores/outbox-model';
import {
  captureOutboxStorageContext,
  clearLocalStateSession,
  deleteLocalDraftsForChannel,
  deleteOutboxCommandsForChannel,
  loadLocalDraft,
  loadOutboxCommand,
  loadOutboxCommands,
  saveLocalDraft,
  saveOutboxCommand,
} from './local-state.service';

type Key = string | Key[];

interface StoreData {
  keyPath: string | null;
  rows: Map<string, { key: Key; value: unknown }>;
  indexes: Map<string, string[]>;
}

interface DatabaseData {
  version: number;
  stores: Map<string, StoreData>;
}

/** A row and where a cursor over it stands: its key, or its index key and key. */
interface Row {
  key: Key;
  position: Key;
  value: unknown;
}

function compareKeys(left: Key, right: Key): number {
  if (typeof left === 'string' || typeof right === 'string') {
    if (typeof left !== 'string') return 1;
    if (typeof right !== 'string') return -1;
    return left < right ? -1 : left > right ? 1 : 0;
  }
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    const order = compareKeys(left[index]!, right[index]!);
    if (order !== 0) return order;
  }
  return left.length - right.length;
}

class MemoryKeyRange {
  private constructor(readonly lower: Key, readonly upper: Key) {}

  static only(key: Key): MemoryKeyRange {
    return new MemoryKeyRange(key, key);
  }

  static bound(lower: Key, upper: Key): MemoryKeyRange {
    return new MemoryKeyRange(lower, upper);
  }

  includes(key: Key): boolean {
    return compareKeys(this.lower, key) <= 0 && compareKeys(key, this.upper) <= 0;
  }
}

class MemoryRequest {
  result: unknown = undefined;
  error: unknown = null;
  onsuccess: (() => void) | null = null;
  onerror: ((event: { preventDefault: () => void }) => void) | null = null;
}

/** Requests run one at a time in the order made; the transaction commits once none is left. */
class MemoryTransaction {
  error: unknown = null;
  oncomplete: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  private readonly queue: Array<() => void> = [];
  private finished = false;

  constructor(readonly database: DatabaseData, private readonly settled?: (committed: boolean) => void) {
    setTimeout(() => this.next());
  }

  objectStore(name: string): MemoryStore {
    const data = this.database.stores.get(name);
    if (!data) throw new DOMException(name, 'NotFoundError');
    return new MemoryStore(this, data);
  }

  request(target: MemoryRequest, operation: () => unknown): MemoryRequest {
    this.queue.push(() => {
      try {
        target.result = operation();
      } catch (error) {
        target.error = error;
        let prevented = false;
        target.onerror?.({ preventDefault: () => { prevented = true; } });
        if (!prevented) {
          this.error = error;
          this.onerror?.();
          this.abort();
        }
        return;
      }
      target.onsuccess?.();
    });
    return target;
  }

  /** Stops the transaction; writes it already made are not rolled back. */
  abort(): void {
    if (this.finished) return;
    this.finished = true;
    this.queue.length = 0;
    if (!this.error) this.error = new DOMException('Transaction aborted', 'AbortError');
    setTimeout(() => {
      this.onabort?.();
      this.settled?.(false);
    });
  }

  private next(): void {
    if (this.finished) return;
    const operation = this.queue.shift();
    if (operation) {
      operation();
      setTimeout(() => this.next());
      return;
    }
    this.finished = true;
    this.oncomplete?.();
    this.settled?.(true);
  }
}

class MemoryStore {
  constructor(private readonly transaction: MemoryTransaction, private readonly data: StoreData) {}

  get indexNames() {
    return { contains: (name: string) => this.data.indexes.has(name) };
  }

  createIndex(name: string, keyPath: string[]): void {
    this.data.indexes.set(name, keyPath);
  }

  deleteIndex(name: string): void {
    this.data.indexes.delete(name);
  }

  get(key: Key): MemoryRequest {
    return this.run(() => structuredClone(this.data.rows.get(JSON.stringify(key))?.value));
  }

  getAllKeys(): MemoryRequest {
    return this.run(() => this.rows().map((row) => row.key));
  }

  put(value: unknown, key?: Key): MemoryRequest {
    return this.run(() => this.write(value, key, true));
  }

  add(value: unknown, key?: Key): MemoryRequest {
    return this.run(() => this.write(value, key, false));
  }

  delete(key: Key): MemoryRequest {
    return this.run(() => { this.data.rows.delete(JSON.stringify(key)); });
  }

  openCursor(): MemoryRequest {
    return this.cursor(() => this.rows());
  }

  index(name: string) {
    const keyPath = this.data.indexes.get(name);
    if (!keyPath) throw new DOMException(name, 'NotFoundError');
    const rows = (range: MemoryKeyRange) => this.indexRows(keyPath).filter((row) => range.includes(row.indexKey));
    return {
      getAll: (range: MemoryKeyRange, count?: number) => this.run(() => (
        rows(range).slice(0, count).map((row) => structuredClone(row.value))
      )),
      count: (range: MemoryKeyRange) => this.run(() => rows(range).length),
      openCursor: (range: MemoryKeyRange) => this.cursor(() => rows(range)),
    };
  }

  private run(operation: () => unknown): MemoryRequest {
    return this.transaction.request(new MemoryRequest(), operation);
  }

  private write(value: unknown, explicitKey: Key | undefined, overwrite: boolean): Key {
    const key = explicitKey ?? (value as Record<string, Key>)[this.data.keyPath!]!;
    const id = JSON.stringify(key);
    if (!overwrite && this.data.rows.has(id)) throw new DOMException(id, 'ConstraintError');
    this.data.rows.set(id, { key, value: structuredClone(value) });
    return key;
  }

  private rows(): Row[] {
    return [...this.data.rows.values()]
      .map((row) => ({ ...row, position: row.key }))
      .sort((left, right) => compareKeys(left.position, right.position));
  }

  private indexRows(keyPath: string[]): Array<Row & { indexKey: Key }> {
    return [...this.data.rows.values()]
      .flatMap((row) => {
        const indexKey = keyPath.map((name) => (row.value as Record<string, unknown>)[name]);
        if (!indexKey.every((part): part is string => typeof part === 'string')) return [];
        return [{ ...row, indexKey, position: [indexKey, row.key] }];
      })
      .sort((left, right) => compareKeys(left.position, right.position));
  }

  /** A cursor walks the live rows, so rows written while it moves are met in key order. */
  private cursor(rows: () => Row[]): MemoryRequest {
    const request = new MemoryRequest();
    const step = (after: Key | null) => this.transaction.request(request, () => {
      const row = rows().find((candidate) => after === null || compareKeys(candidate.position, after) > 0);
      return row
        ? {
          key: row.key,
          primaryKey: row.key,
          value: structuredClone(row.value),
          delete: () => this.delete(row.key),
          continue: () => { step(row.position); },
        }
        : null;
    });
    step(null);
    return request;
  }
}

class MemoryConnection {
  upgrade: MemoryTransaction | null = null;

  constructor(private readonly database: DatabaseData) {}

  get objectStoreNames() {
    return { contains: (name: string) => this.database.stores.has(name) };
  }

  createObjectStore(name: string, options: { keyPath?: string } = {}): MemoryStore {
    const data: StoreData = { keyPath: options.keyPath ?? null, rows: new Map(), indexes: new Map() };
    this.database.stores.set(name, data);
    return new MemoryStore(this.upgrade!, data);
  }

  transaction(): MemoryTransaction {
    return new MemoryTransaction(this.database);
  }

  close(): void {
    // Nothing is held open.
  }
}

class MemoryOpenRequest extends MemoryRequest {
  transaction: MemoryTransaction | null = null;
  onupgradeneeded: ((event: { oldVersion: number; newVersion: number }) => void) | null = null;
}

function memoryIndexedDb() {
  const databases = new Map<string, DatabaseData>();
  let opening = Promise.resolve();
  return {
    open(name: string, version?: number): MemoryOpenRequest {
      const request = new MemoryOpenRequest();
      // Opens are served in order, so one made during an upgrade waits for it.
      opening = opening.then(() => new Promise<void>((served) => setTimeout(() => {
        const database = databases.get(name) ?? { version: 0, stores: new Map<string, StoreData>() };
        databases.set(name, database);
        const target = version ?? Math.max(database.version, 1);
        if (target < database.version) {
          request.error = new DOMException(name, 'VersionError');
          request.onerror?.({ preventDefault: () => undefined });
          served();
          return;
        }
        const connection = new MemoryConnection(database);
        request.result = connection;
        if (target === database.version) {
          request.onsuccess?.();
          served();
          return;
        }
        const oldVersion = database.version;
        database.version = target;
        connection.upgrade = new MemoryTransaction(database, (committed) => {
          request.transaction = null;
          if (committed) {
            request.onsuccess?.();
          } else {
            database.version = oldVersion;
            request.error = new DOMException(name, 'AbortError');
            request.onerror?.({ preventDefault: () => undefined });
          }
          served();
        });
        request.transaction = connection.upgrade;
        request.onupgradeneeded?.({ oldVersion, newVersion: target });
      })));
      return request;
    },
  };
}

function settled<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function completed(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

interface Owner {
  userId: string;
  deviceId: string;
}

const userId = '11111111-1111-4111-8111-111111111111';
const deviceId = '22222222-2222-4222-8222-222222222222';
const earlierDeviceId = '44444444-4444-4444-8444-444444444444';
const otherUserId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherUserDeviceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const channelId = '33333333-3333-4333-8333-333333333333';
const otherChannelId = '55555555-5555-4555-8555-555555555555';
const postScope = forumPostDraftScope(channelId, '66666666-6666-4666-8666-666666666666');
const thisDevice: Owner = { userId, deviceId };
const earlierDevice: Owner = { userId, deviceId: earlierDeviceId };
const otherUser: Owner = { userId: otherUserId, deviceId: otherUserDeviceId };
const SAVED_AT = '2026-10-01T00:00:00.000Z';

/** Before version 3 a record id named only the user; now it also names the device. */
const userScopedId = (owner: Owner, scope: string) => `${owner.userId}:${scope}`;
const deviceScopedId = (owner: Owner, scope: string) => `${owner.userId}:${owner.deviceId}:${scope}`;

interface SavedRecord {
  owner: Owner;
  purpose: 'draft' | 'outbox';
  scope: string;
  channelId: string;
  payload: unknown;
  id: string;
  createdAt: string;
  updatedAt: string;
}

function savedDraft(owner: Owner, scope: string, content: string, change: Partial<SavedRecord> = {}): SavedRecord {
  return {
    owner,
    purpose: 'draft',
    scope,
    channelId: draftScopeChannelId(scope),
    payload: { version: 1, content },
    id: userScopedId(owner, scope),
    createdAt: SAVED_AT,
    updatedAt: SAVED_AT,
    ...change,
  };
}

function savedCommand(owner: Owner, command: OutboxCommand, change: Partial<SavedRecord> = {}): SavedRecord {
  return {
    owner,
    purpose: 'outbox',
    scope: command.idempotencyKey,
    channelId: command.channelId,
    payload: command,
    id: userScopedId(owner, command.idempotencyKey),
    createdAt: command.createdAt,
    updatedAt: command.createdAt,
    ...change,
  };
}

const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

/** Seal a record the way clients before version 3 did, under its device's local key. */
async function seal(key: CryptoKey, record: SavedRecord) {
  const { owner, purpose, scope } = record;
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: nonce,
    additionalData: new TextEncoder().encode(JSON.stringify([1, purpose, owner.userId, owner.deviceId, scope])),
    tagLength: 128,
  }, key, new TextEncoder().encode(JSON.stringify(record.payload)));
  return {
    id: record.id,
    version: 1,
    purpose,
    ownerId: owner.userId,
    deviceId: owner.deviceId,
    channelId: record.channelId,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    nonce: base64(nonce),
    ciphertext: base64(new Uint8Array(ciphertext)),
  };
}

/** A version 2 database as earlier clients left it in the browser profile. */
async function writeVersion2Profile(records: readonly SavedRecord[]): Promise<void> {
  const keys = new Map<string, { owner: Owner; key: CryptoKey }>();
  for (const { owner } of records) {
    const id = `${owner.userId}:${owner.deviceId}`;
    if (keys.has(id)) continue;
    keys.set(id, { owner, key: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) });
  }
  const sealed = await Promise.all(records.map((record) => (
    seal(keys.get(`${record.owner.userId}:${record.owner.deviceId}`)!.key, record)
  )));
  const opening = indexedDB.open('alparts-local-state', 2);
  opening.onupgradeneeded = () => {
    const db = opening.result;
    db.createObjectStore('crypto');
    db.createObjectStore('drafts', { keyPath: 'id' });
    const outbox = db.createObjectStore('outbox', { keyPath: 'id' });
    outbox.createIndex('owner-device-created', ['ownerId', 'deviceId', 'createdAt'], { unique: false });
    outbox.createIndex('owner-device-channel', ['ownerId', 'deviceId', 'channelId'], { unique: false });
  };
  const db = await settled(opening);
  const tx = db.transaction(['crypto', 'drafts', 'outbox'], 'readwrite');
  for (const [id, { owner, key }] of keys) tx.objectStore('crypto').put({ version: 1, ...owner, key }, id);
  for (const record of sealed) tx.objectStore(record.purpose === 'draft' ? 'drafts' : 'outbox').put(record);
  await completed(tx);
  db.close();
}

async function storedIds(storeName: 'drafts' | 'outbox'): Promise<IDBValidKey[]> {
  const db = await settled(indexedDB.open('alparts-local-state'));
  try {
    return await settled(db.transaction(storeName, 'readonly').objectStore(storeName).getAllKeys());
  } finally {
    db.close();
  }
}

beforeEach(() => {
  vi.stubGlobal('indexedDB', memoryIndexedDb());
  vi.stubGlobal('IDBKeyRange', MemoryKeyRange);
  clearLocalStateSession();
  device.active = thisDevice;
});

afterEach(() => {
  clearLocalStateSession();
  vi.unstubAllGlobals();
});

describe('records saved before the device was part of their id', () => {
  it('loads a queued message and drafts after the upgrade', async () => {
    const command = createOutboxCommand({ channelId, content: 'queued while offline' });
    await writeVersion2Profile([
      savedCommand(thisDevice, command),
      savedDraft(thisDevice, channelId, 'channel draft'),
      savedDraft(thisDevice, postScope, 'reply draft'),
    ]);
    const context = captureOutboxStorageContext();
    // Loads at startup may overlap the upgrade.
    const [commands, channelDraft, replyDraft] = await Promise.all([
      loadOutboxCommands(context),
      loadLocalDraft(channelId),
      loadLocalDraft(postScope),
    ]);
    expect(commands).toEqual([command]);
    expect(channelDraft).toBe('channel draft');
    expect(replyDraft).toBe('reply draft');
    expect(await loadOutboxCommand(context, command.idempotencyKey)).toEqual(command);
    expect(await storedIds('outbox')).toEqual([deviceScopedId(thisDevice, command.idempotencyKey)]);
  });

  it('keeps the later write when both id layouts hold the same draft', async () => {
    await writeVersion2Profile([
      savedDraft(thisDevice, channelId, 'before the update'),
      savedDraft(thisDevice, channelId, 'after the update', {
        id: deviceScopedId(thisDevice, channelId),
        updatedAt: '2026-10-02T00:00:00.000Z',
      }),
      savedDraft(thisDevice, postScope, 'from a tab still on the old version', { updatedAt: '2026-10-03T00:00:00.000Z' }),
      savedDraft(thisDevice, postScope, 'after the update', {
        id: deviceScopedId(thisDevice, postScope),
        updatedAt: '2026-10-02T00:00:00.000Z',
      }),
    ]);
    expect(await loadLocalDraft(channelId)).toBe('after the update');
    expect(await loadLocalDraft(postScope)).toBe('from a tab still on the old version');
    expect(await storedIds('drafts')).toEqual([
      deviceScopedId(thisDevice, channelId),
      deviceScopedId(thisDevice, postScope),
    ]);
  });

  it('erases a revoked channel in either layout, also what an earlier device of the user saved', async () => {
    const earlierRevoked = createOutboxCommand({ channelId, content: 'queued on the earlier device' });
    const earlierKept = createOutboxCommand({ channelId: otherChannelId, content: 'queued on the earlier device for an open channel' });
    const otherUserCommand = createOutboxCommand({ channelId, content: 'queued by another account in this browser' });
    await writeVersion2Profile([
      savedDraft(earlierDevice, channelId, 'earlier device draft'),
      savedDraft(earlierDevice, otherChannelId, 'draft in a channel still open'),
      savedDraft(thisDevice, postScope, 'reply draft'),
      savedDraft(otherUser, channelId, 'another account in this browser'),
      savedCommand(earlierDevice, earlierRevoked),
      savedCommand(earlierDevice, earlierKept),
      savedCommand(otherUser, otherUserCommand),
    ]);
    const context = captureOutboxStorageContext();
    const revoked = createOutboxCommand({ channelId, content: 'queued for the revoked channel' });
    const kept = createOutboxCommand({ channelId: otherChannelId, content: 'queued for an open channel' });
    await saveLocalDraft(channelId, 'this device draft');
    await saveOutboxCommand(context, revoked, () => true);
    await saveOutboxCommand(context, kept, () => true);

    await Promise.all([deleteLocalDraftsForChannel(channelId), deleteOutboxCommandsForChannel(context, channelId)]);

    expect(await storedIds('drafts')).toEqual([
      deviceScopedId(earlierDevice, otherChannelId),
      deviceScopedId(otherUser, channelId),
    ]);
    expect(await storedIds('outbox')).toEqual([
      deviceScopedId(thisDevice, kept.idempotencyKey),
      deviceScopedId(earlierDevice, earlierKept.idempotencyKey),
      deviceScopedId(otherUser, otherUserCommand.idempotencyKey),
    ]);
    expect(await loadOutboxCommands(context)).toEqual([kept]);
  });

  it('leaves a queued message whose id follows neither layout untouched', async () => {
    const command = createOutboxCommand({ channelId, content: 'queued' });
    await writeVersion2Profile([savedCommand(thisDevice, command, { id: `queued:${command.idempotencyKey}` })]);
    expect(await loadOutboxCommands(captureOutboxStorageContext())).toEqual([]);
    expect(await storedIds('outbox')).toEqual([`queued:${command.idempotencyKey}`]);
  });
});

describe('devices of one user in one browser profile', () => {
  it('never overwrite or delete each other\'s drafts and queued messages', async () => {
    device.active = earlierDevice;
    const command = createOutboxCommand({ channelId, content: 'queued on the earlier device' });
    await saveLocalDraft(channelId, 'earlier device draft');
    await saveOutboxCommand(captureOutboxStorageContext(), command, () => true);

    device.active = thisDevice;
    const context = captureOutboxStorageContext();
    expect(await loadLocalDraft(channelId)).toBeNull();
    expect(await loadOutboxCommands(context)).toEqual([]);
    expect(await loadOutboxCommand(context, command.idempotencyKey)).toBeNull();
    await saveLocalDraft(channelId, 'this device draft');

    device.active = earlierDevice;
    expect(await loadLocalDraft(channelId)).toBe('earlier device draft');
    expect(await loadOutboxCommands(captureOutboxStorageContext())).toEqual([command]);
    device.active = thisDevice;
    expect(await loadLocalDraft(channelId)).toBe('this device draft');
  });

  it('count only their own queued messages toward the outbox limit', async () => {
    await writeVersion2Profile(Array.from({ length: MAX_OUTBOX_COMMANDS_PER_DEVICE }, () => (
      savedCommand(earlierDevice, createOutboxCommand({ channelId, content: 'queued on the earlier device' }))
    )));
    const context = captureOutboxStorageContext();
    const command = createOutboxCommand({ channelId, content: 'queued on this device' });
    await saveOutboxCommand(context, command, () => true);
    expect(await loadOutboxCommands(context)).toEqual([command]);
  });
});
