import { openDB } from 'idb';
import { channelKeyScopes, type ChannelKeyScopeToken } from './channel-key-scope';
import { getLocalKey } from './local-state.service';
export interface SecurityOwner {
  userId: string;
  deviceId: string;
}
export const toBase64 = (bytes: Uint8Array): string => {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
};
export const fromBase64 = (value: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
export const sha256 = async (value: string | Uint8Array): Promise<string> => {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>)),
    (b) => b.toString(16).padStart(2, '0'),
  ).join('');
};
async function database() {
  return openDB('alparts-security', 1, {
    upgrade(db) {
      db.createObjectStore('records');
    },
  });
}
export async function readSecurityState<T>(owner: SecurityOwner, name: string): Promise<T | null> {
  const db = await database();
  const id = `${owner.userId}:${owner.deviceId}:${name}`;
  try {
    const record = await db.get('records', id);
    if (!record) return null;
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromBase64(record.nonce),
        additionalData: new TextEncoder().encode(id),
      },
      await getLocalKey(owner),
      fromBase64(record.ciphertext),
    );
    try {
      return JSON.parse(new TextDecoder().decode(plain)) as T;
    } finally {
      new Uint8Array(plain).fill(0);
    }
  } finally {
    db.close();
  }
}
export async function writeSecurityState(
  owner: SecurityOwner,
  name: string,
  value: unknown,
  capturedScope?: ChannelKeyScopeToken,
): Promise<void> {
  const channelId =
    /^(?:mls-package|mls-proposal|mls-key|mls-head|key-commitment|recovered|recovery-backup-pending|recovery-sent):([a-f0-9-]{36})(?::|$)/.exec(
      name,
    )?.[1];
  const scope = capturedScope ?? (channelId ? channelKeyScopes.capture(channelId) : undefined);
  if (scope) channelKeyScopes.assertCurrent(scope);
  const id = `${owner.userId}:${owner.deviceId}:${name}`;
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(value));
  if (plain.length > 2 * 1024 * 1024) throw new Error('SECURITY_STORAGE_LIMIT');
  try {
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: new TextEncoder().encode(id),
      },
      await getLocalKey(owner),
      plain,
    );
    const db = await database();
    try {
      if (scope) channelKeyScopes.assertCurrent(scope);
      await db.put(
        'records',
        {
          nonce: toBase64(nonce),
          ciphertext: toBase64(new Uint8Array(ciphertext)),
        },
        id,
      );
      if (scope && !channelKeyScopes.isCurrent(scope)) {
        await db.delete('records', id);
        channelKeyScopes.assertCurrent(scope);
      }
    } finally {
      db.close();
    }
  } finally {
    plain.fill(0);
  }
}
export async function deleteSecurityState(owner: SecurityOwner, name: string): Promise<void> {
  const db = await database();
  try {
    await db.delete('records', `${owner.userId}:${owner.deviceId}:${name}`);
  } finally {
    db.close();
  }
}

/** Called after synchronous scope invalidation; late writers also check it. */
export async function deleteChannelSecurityState(
  owner: SecurityOwner,
  channelId: string,
): Promise<void> {
  const db = await database();
  try {
    const tx = db.transaction('records', 'readwrite');
    const prefix = `${owner.userId}:${owner.deviceId}:`;
    for await (const cursor of tx.store.iterate(IDBKeyRange.bound(prefix, `${prefix}\uffff`))) {
      const name = String(cursor.key).slice(prefix.length);
      if (name.split(':')[1] === channelId) await cursor.delete();
    }
    await tx.done;
  } finally {
    db.close();
  }
}

/** Names (without owner prefix) of this device's records that start with `prefix`. */
export async function listSecurityStateNames(owner: SecurityOwner, prefix: string, limit: number): Promise<string[]> {
  const db = await database();
  try {
    const ownerPrefix = `${owner.userId}:${owner.deviceId}:`;
    const start = `${ownerPrefix}${prefix}`;
    const keys = await db.getAllKeys('records', IDBKeyRange.bound(start, `${start}￿`), limit);
    return keys.map((key) => String(key).slice(ownerPrefix.length));
  } finally {
    db.close();
  }
}
