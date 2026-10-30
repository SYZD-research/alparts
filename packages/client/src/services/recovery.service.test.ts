import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { serializeHistoryKeyBackup } from '@alparts/shared';

// Recovery plans are created, turned on and restored against an in-memory
// server. The passkey prompt is stubbed, with and without the passkey
// support that keeps the recovery secret. Like the real server, the in-memory
// one refuses a record the device did not sign, keeps the first record it
// receives for a version and says whether it stored a record or held one.

interface StoredRecord {
  generation: string;
  channelId: string;
  version: number;
  keyCommitment: string;
  ciphertext: string;
}

const mocks = vi.hoisted(() => {
  let deviceKeys: Promise<CryptoKeyPair> | undefined;
  return {
    owner: { userId: '11111111-1111-4111-8111-111111111111', deviceId: 'device', approved: true, identityKey: 'identity' },
    // This device's signing key, made when first needed.
    signingKeys: () => (deviceKeys ??= crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])),
    signed: [] as string[],
    storage: new Map<string, string>(),
    server: {
      passkeys: [] as Array<{ id: string }>,
      config: null as { generation: string; signingKey: string; encryptedSecret: string } | null,
      keys: [] as StoredRecord[],
      candidates: [] as Array<{ channelId: string; version: number }>,
      // Versions the server stores but leaves out of its answer.
      unanswered: new Set<string>(),
      // Refuses every upload, as a server does for a record it cannot accept.
      refuseUploads: false,
      restoreRequests: 0,
    },
    restored: [] as Array<[string, number, number[]]>,
    credentialGet: vi.fn(),
  };
});

vi.mock('./api', async (importOriginal) => {
  const original = await importOriginal<typeof import('./api')>();
  return {
    ...original,
    api: {
      securityRequest: async (path: string, body?: unknown) => {
        const { server } = mocks;
        if (path === '/auth/passkeys') return server.passkeys;
        if (path === '/auth/passkeys/vault') return { rpId: 'example.test' };
        if (path === '/recovery/configure') {
          server.config = body as typeof server.config;
          return { success: true };
        }
        if (path === '/recovery/passkey' && server.config) {
          const { passkeyWrap } = body as { passkeyWrap: unknown };
          server.config.encryptedSecret = JSON.stringify({ ...JSON.parse(server.config.encryptedSecret), passkeyWrap });
          return { success: true };
        }
        if (path === '/recovery/restore-device') {
          server.restoreRequests++;
          return { success: true };
        }
        if (path === '/recovery/metadata' && server.config) {
          const { generation, signingKey, encryptedSecret } = server.config;
          // As sent by the server: a plan without a passkey has no passkeyWrap.
          return JSON.parse(JSON.stringify({
            generation, signingKey, accessConfigured: true, passkeyWrap: JSON.parse(encryptedSecret).passkeyWrap,
          }));
        }
        if (path === '/recovery' && server.config) {
          return { ...server.config, userId: mocks.owner.userId, createdAt: '2026-10-01T00:00:00.000Z', accessConfigured: true };
        }
        if (path === '/recovery/candidates') return { candidates: server.candidates, cursor: null };
        if (path === '/recovery/keys' && body === undefined) {
          const keys = [...server.keys].sort((a, b) => a.channelId.localeCompare(b.channelId) || a.version - b.version);
          return { keys, cursor: null };
        }
        if (path === '/recovery/keys') {
          if (server.refuseUploads) throw new original.ApiError('refused', 403, 'RECOVERY_FAILED');
          const { keys } = body as { keys: Array<StoredRecord & { signature: string }> };
          const results = [];
          for (const { signature, ...record } of keys) {
            const { publicKey } = await mocks.signingKeys();
            const payload = serializeHistoryKeyBackup({
              userId: mocks.owner.userId,
              generation: record.generation,
              channelId: record.channelId,
              version: record.version,
              keyCommitment: record.keyCommitment,
              ciphertextHash: await sha256Base64Url(new TextEncoder().encode(record.ciphertext)),
            });
            const genuine = await crypto.subtle.verify(
              { name: 'ECDSA', hash: 'SHA-256' },
              publicKey,
              Uint8Array.from(atob(signature), (c) => c.charCodeAt(0)),
              new TextEncoder().encode(payload),
            );
            if (!genuine) throw new original.ApiError('refused', 403, 'RECOVERY_FAILED');
            const held = server.keys.some((key) => key.channelId === record.channelId && key.version === record.version);
            if (!held) server.keys.push(record);
            if (!server.unanswered.has(`${record.channelId}:${record.version}`)) {
              results.push({ channelId: record.channelId, version: record.version, status: held ? 'present' : 'stored' });
            }
          }
          return { results };
        }
        throw new Error(`Unexpected request ${path}`);
      },
    },
  };
});

vi.mock('./crypto.service', () => ({
  getActiveDevice: () => mocks.owner,
  signDevicePayload: async (payload: string) => {
    mocks.signed.push(payload);
    const { privateKey } = await mocks.signingKeys();
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(payload));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  },
  saveRecoveredChannelKey: async (channelId: string, version: number, key: Uint8Array) => {
    mocks.restored.push([channelId, version, Array.from(key)]);
  },
  exportHistoryKey: vi.fn(),
}));

vi.mock('./directory.service', () => ({
  verifiedDirectory: async () => ({
    head: { userId: mocks.owner.userId, sequence: 1, hash: '0'.repeat(64) },
    recovery: mocks.server.config && {
      generation: mocks.server.config.generation,
      signingKey: mocks.server.config.signingKey,
    },
    devices: {},
  }),
}));

vi.mock('./security-storage', async (importOriginal) => ({
  ...await importOriginal<typeof import('./security-storage')>(),
  readSecurityState: async (_owner: unknown, name: string) => {
    const value = mocks.storage.get(name);
    return value === undefined ? null : JSON.parse(value);
  },
  writeSecurityState: async (_owner: unknown, name: string, value: unknown) => {
    mocks.storage.set(name, JSON.stringify(value));
  },
  deleteSecurityState: async (_owner: unknown, name: string) => {
    mocks.storage.delete(name);
  },
}));

import {
  backupAvailableHistory,
  backupRawHistoryKey,
  createRecoveryPlan,
  enableHistoryRecovery,
  protectHistoryWithPasskey,
  restoreHistory,
  restoreHistoryWithPasskey,
} from './recovery.service';
import { deriveArchiveKey, unwrapArchiveKey } from './passkey-vault';
import { exportHistoryKey } from './crypto.service';
import { aad, aes, seal } from './recovery-crypto';
import { fromBase64 } from './security-storage';

const credentialId = 'YWxwYXJ0cy10ZXN0LWNyZWRlbnRpYWw';
const channelId = '22222222-2222-4222-8222-222222222222';
const passkeySecret = crypto.getRandomValues(new Uint8Array(32));
const keepsSecret = async () => ({
  id: credentialId,
  getClientExtensionResults: () => ({ prf: { results: { first: passkeySecret.slice().buffer } } }),
});
const cannotKeepSecret = async () => ({ id: credentialId, getClientExtensionResults: () => ({}) });
const envelope = (plan: { encryptedSecret: string }) => JSON.parse(plan.encryptedSecret);
async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

beforeEach(() => {
  mocks.storage.clear();
  mocks.signed = [];
  mocks.server.passkeys = [];
  mocks.server.config = null;
  mocks.server.keys = [];
  mocks.server.candidates = [];
  mocks.server.unanswered = new Set();
  mocks.server.refuseUploads = false;
  mocks.server.restoreRequests = 0;
  mocks.owner.approved = true;
  mocks.restored = [];
  vi.mocked(exportHistoryKey).mockReset();
  vi.stubGlobal('window', { isSecureContext: true, location: { protocol: 'https:', hostname: 'chat.example.test' } });
  vi.stubGlobal('navigator', { credentials: { get: mocks.credentialGet } });
  mocks.credentialGet.mockImplementation(keepsSecret);
});
afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

describe('creating a recovery plan', () => {
  it('works for an account without passkeys, without asking for one', async () => {
    const prompt = vi.fn();
    const plan = await createRecoveryPlan(prompt);
    expect(plan.passkeyProtected).toBe(false);
    expect(envelope(plan)).not.toHaveProperty('passkeyWrap');
    expect(prompt).not.toHaveBeenCalled();
    expect(mocks.credentialGet).not.toHaveBeenCalled();
  });

  it('does not ask for a passkey where none can be used, such as the desktop app', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    vi.stubGlobal('window', { isSecureContext: true, location: { protocol: 'alparts-app:', hostname: 'bundle' } });
    const prompt = vi.fn();
    const plan = await createRecoveryPlan(prompt);
    expect(plan.passkeyProtected).toBe(false);
    expect(envelope(plan)).not.toHaveProperty('passkeyWrap');
    expect(prompt).not.toHaveBeenCalled();
    expect(mocks.credentialGet).not.toHaveBeenCalled();
  });

  it('includes a passkey that can keep the secret, announcing the prompt just before it appears', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    const order: string[] = [];
    mocks.credentialGet.mockImplementation(async () => {
      order.push('prompt');
      return keepsSecret();
    });
    const plan = await createRecoveryPlan(() => order.push('announced'));
    expect(plan.passkeyProtected).toBe(true);
    expect(envelope(plan).passkeyWrap.credentialId).toBe(credentialId);
    expect(order).toEqual(['announced', 'prompt']);
  });

  it('reports a code-only plan after a prompt with a passkey that cannot keep the secret', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    mocks.credentialGet.mockImplementation(cannotKeepSecret);
    const prompt = vi.fn();
    const plan = await createRecoveryPlan(prompt);
    expect(prompt).toHaveBeenCalledOnce();
    expect(plan.passkeyProtected).toBe(false);
    expect(envelope(plan)).not.toHaveProperty('passkeyWrap');
  });

  it('offers a code-only plan when the passkey prompt is cancelled', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    mocks.credentialGet.mockRejectedValue(
      new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'),
    );
    const plan = await createRecoveryPlan();
    expect(plan.passkeyProtected).toBe(false);
    expect(envelope(plan)).not.toHaveProperty('passkeyWrap');
  });

  it('still fails on other passkey errors', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    mocks.credentialGet.mockRejectedValue(new DOMException('The relying party is not valid.', 'SecurityError'));
    await expect(createRecoveryPlan()).rejects.toThrow('The relying party is not valid.');
  });
});

describe('backing up history keys', () => {
  const sentMarker = (version: number) => `recovery-sent:${channelId}:${version}`;
  const pendingMarker = (version: number) => `recovery-backup-pending:${channelId}:${version}`;
  const randomKey = () => crypto.getRandomValues(new Uint8Array(32));

  async function turnOn() {
    const plan = await createRecoveryPlan();
    await enableHistoryRecovery(plan);
    return plan;
  }

  it('signs each record with the device key over who, what and the encrypted record itself', async () => {
    await turnOn();
    mocks.signed = [];
    const key = randomKey();
    await backupRawHistoryKey(channelId, 1, key.slice());
    // The server takes the record only because its signature verifies over this payload.
    expect(mocks.server.keys).toHaveLength(1);
    const [record] = mocks.server.keys;
    expect(mocks.signed).toEqual([
      serializeHistoryKeyBackup({
        userId: mocks.owner.userId,
        generation: record.generation,
        channelId,
        version: 1,
        keyCommitment: await sha256Base64Url(key),
        ciphertextHash: await sha256Base64Url(new TextEncoder().encode(record.ciphertext)),
      }),
    ]);
  });

  it('marks a version as saved once the server stored it', async () => {
    await turnOn();
    mocks.storage.set(pendingMarker(1), 'true');
    await backupRawHistoryKey(channelId, 1, randomKey());
    expect(mocks.storage.has(sentMarker(1))).toBe(true);
    expect(mocks.storage.has(pendingMarker(1))).toBe(false);
  });

  it('marks a version as saved when the server already held a record of it, and keeps that record', async () => {
    await turnOn();
    const key = randomKey();
    await backupRawHistoryKey(channelId, 1, key.slice());
    const [first] = mocks.server.keys;
    // Another device, or this one after a lost answer, sends the version again.
    mocks.storage.delete(sentMarker(1));
    mocks.storage.set(pendingMarker(1), 'true');
    await backupRawHistoryKey(channelId, 1, key.slice());
    expect(mocks.server.keys).toEqual([first]);
    expect(mocks.storage.has(sentMarker(1))).toBe(true);
    expect(mocks.storage.has(pendingMarker(1))).toBe(false);
  });

  it('does not mark a version as saved when the server did not say it holds one', async () => {
    await turnOn();
    mocks.server.unanswered.add(`${channelId}:1`);
    mocks.storage.set(pendingMarker(1), 'true');
    await expect(backupRawHistoryKey(channelId, 1, randomKey())).rejects.toThrow('RECOVERY_BACKUP_UNCONFIRMED');
    expect(mocks.storage.has(sentMarker(1))).toBe(false);
    expect(mocks.storage.has(pendingMarker(1))).toBe(true);
  });

  it('does not mark a version as saved when the server refuses the record', async () => {
    await turnOn();
    mocks.server.refuseUploads = true;
    mocks.storage.set(pendingMarker(1), 'true');
    await expect(backupRawHistoryKey(channelId, 1, randomKey())).rejects.toMatchObject({ status: 403 });
    expect(mocks.storage.has(sentMarker(1))).toBe(false);
    expect(mocks.storage.has(pendingMarker(1))).toBe(true);
  });

  it('marks only the versions of a batch the server stored or held, and sends the rest again next time', async () => {
    await turnOn();
    const keys = new Map([1, 2, 3].map((version) => [version, randomKey()]));
    mocks.server.candidates = [...keys.keys()].map((version) => ({ channelId, version }));
    vi.mocked(exportHistoryKey).mockImplementation(async (_channel, version) => keys.get(version)!.slice());
    // Version 1 is already in the archive; the server leaves version 3 out of its answer.
    await backupRawHistoryKey(channelId, 1, keys.get(1)!.slice());
    mocks.storage.delete(sentMarker(1));
    mocks.server.unanswered.add(`${channelId}:3`);
    expect(await backupAvailableHistory()).toBe(2);
    expect([1, 2, 3].map((version) => mocks.storage.has(sentMarker(version)))).toEqual([true, true, false]);
    // Nothing is left out of the next answer: the missing version is sent again, the others are not.
    mocks.server.unanswered.clear();
    mocks.signed = [];
    expect(await backupAvailableHistory()).toBe(1);
    expect(mocks.signed).toHaveLength(1);
    expect([1, 2, 3].map((version) => mocks.storage.has(sentMarker(version)))).toEqual([true, true, true]);
  });
});

describe('restoring history from a plan', () => {
  // Turns the plan on, backs up one history key, then forgets this device's copy.
  async function turnOnWithOneKey(plan: Awaited<ReturnType<typeof createRecoveryPlan>>) {
    await enableHistoryRecovery(plan);
    const key = crypto.getRandomValues(new Uint8Array(32));
    await backupRawHistoryKey(channelId, 1, key.slice());
    mocks.storage.clear();
    return Array.from(key);
  }

  it('restores a code-only plan with the recovery code, but not with a passkey', async () => {
    const plan = await createRecoveryPlan();
    const key = await turnOnWithOneKey(plan);
    await expect(restoreHistoryWithPasskey()).rejects.toThrow('INVALID_PASSKEY_WRAP');
    expect(await restoreHistory(plan.code)).toEqual({ restored: 1, failed: 0 });
    expect(mocks.restored).toEqual([[channelId, 1, key]]);
  });

  it('restores a plan that includes a passkey with the passkey on an approved device', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    const plan = await createRecoveryPlan();
    const key = await turnOnWithOneKey(plan);
    expect(await restoreHistoryWithPasskey()).toEqual({ restored: 1, failed: 0 });
    expect(mocks.restored).toEqual([[channelId, 1, key]]);
  });

  it('does not let the passkey approve a device: it keeps the history key, not the recovery code', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    const plan = await createRecoveryPlan();
    await turnOnWithOneKey(plan);
    const { generation } = plan;
    const opened = await unwrapArchiveKey(envelope(plan).passkeyWrap, mocks.owner.userId, generation);
    const code = Uint8Array.from(plan.code.replace(/-/g, '').match(/../g)!, (b) => parseInt(b, 16));
    expect(opened).toEqual(await deriveArchiveKey(code, mocks.owner.userId, generation));
    expect(opened).not.toEqual(code);
    // A device waiting for approval is told to use the code or another device.
    mocks.owner.approved = false;
    mocks.signed = [];
    await expect(restoreHistoryWithPasskey()).rejects.toThrow('RECOVERY_CODE_REQUIRED');
    expect(mocks.server.restoreRequests).toBe(0);
    expect(mocks.restored).toEqual([]);
  });

  it('never opens a wrap of the recovery code made before 2026-10-30', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    const plan = await createRecoveryPlan();
    await turnOnWithOneKey(plan);
    const secret = JSON.parse(mocks.server.config!.encryptedSecret);
    mocks.server.config!.encryptedSecret = JSON.stringify({ ...secret, passkeyWrap: { ...secret.passkeyWrap, version: 1 } });
    await expect(restoreHistoryWithPasskey()).rejects.toThrow('INVALID_PASSKEY_WRAP');
    expect(mocks.restored).toEqual([]);
  });

  it('lets an approved device that keeps the history key wrap it with a passkey later', async () => {
    const plan = await createRecoveryPlan();
    await enableHistoryRecovery(plan);
    const key = crypto.getRandomValues(new Uint8Array(32));
    await backupRawHistoryKey(channelId, 1, key.slice());
    mocks.server.passkeys = [{ id: credentialId }];
    await protectHistoryWithPasskey();
    expect(JSON.parse(mocks.server.config!.encryptedSecret).passkeyWrap.version).toBe(2);
    mocks.storage.clear();
    expect(await restoreHistoryWithPasskey()).toEqual({ restored: 1, failed: 0 });
    expect(mocks.restored).toEqual([[channelId, 1, Array.from(key)]]);
  });

  it('does not wrap a history key this device does not keep', async () => {
    const plan = await createRecoveryPlan();
    await enableHistoryRecovery(plan);
    mocks.storage.clear();
    mocks.server.passkeys = [{ id: credentialId }];
    await expect(protectHistoryWithPasskey()).rejects.toThrow('RECOVERY_CODE_REQUIRED');
    expect(JSON.parse(mocks.server.config!.encryptedSecret)).not.toHaveProperty('passkeyWrap');
  });

  it('skips records that are not genuine backups and restores the ones after them', async () => {
    const plan = await createRecoveryPlan();
    await enableHistoryRecovery(plan);
    const archive = JSON.parse(mocks.storage.get('recovery')!) as { generation: string; key: string };
    const archiveKey = await aes(fromBase64(archive.key));
    const record = async (version: number, raw: Uint8Array, options: { commitment?: string; generation?: string } = {}) => {
      const keyCommitment = options.commitment ?? await sha256Base64Url(raw);
      const generation = options.generation ?? archive.generation;
      return {
        generation,
        channelId,
        version,
        keyCommitment,
        ciphertext: await seal(archiveKey, raw, aad(mocks.owner.userId, `${generation}:${channelId}:${version}:${keyCommitment}`)),
      };
    };
    const keys = [2, 4].map(() => crypto.getRandomValues(new Uint8Array(32)));
    const other = crypto.getRandomValues(new Uint8Array(32));
    mocks.server.keys = [
      // What another session once wrote in the archive's place.
      { generation: archive.generation, channelId, version: 1, keyCommitment: await sha256Base64Url(other), ciphertext: btoa('A'.repeat(80)) },
      await record(2, keys[0]),
      // Sealed properly, but not the key its commitment names.
      await record(3, other, { commitment: await sha256Base64Url(crypto.getRandomValues(new Uint8Array(32))) }),
      await record(4, keys[1]),
      // A record of another recovery code, and one that is not even base64.
      await record(5, other, { generation: crypto.randomUUID() }),
      { generation: archive.generation, channelId, version: 6, keyCommitment: await sha256Base64Url(other), ciphertext: '!'.repeat(80) },
    ];
    mocks.storage.clear();
    expect(await restoreHistory(plan.code)).toEqual({ restored: 2, failed: 4 });
    expect(mocks.restored).toEqual([
      [channelId, 2, Array.from(keys[0])],
      [channelId, 4, Array.from(keys[1])],
    ]);
    // The device can keep saving history under this code after a partial restore.
    expect(JSON.parse(mocks.storage.get('recovery')!)).toEqual(archive);
  });
});
