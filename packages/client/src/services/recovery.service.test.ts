import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Recovery plans are created, turned on and restored against an in-memory
// server. The passkey prompt is stubbed, with and without the passkey
// support that keeps the recovery secret.

const mocks = vi.hoisted(() => ({
  owner: { userId: '11111111-1111-4111-8111-111111111111', deviceId: 'device', approved: true, identityKey: 'identity' },
  storage: new Map<string, string>(),
  server: {
    passkeys: [] as Array<{ id: string }>,
    config: null as { generation: string; signingKey: string; encryptedSecret: string } | null,
    keys: [] as unknown[],
  },
  restored: [] as Array<[string, number, number[]]>,
  credentialGet: vi.fn(),
}));

vi.mock('./api', async (importOriginal) => ({
  ...await importOriginal<typeof import('./api')>(),
  api: {
    securityRequest: async (path: string, body?: unknown) => {
      const { server } = mocks;
      if (path === '/auth/passkeys') return server.passkeys;
      if (path === '/auth/passkeys/vault') return { rpId: 'example.test' };
      if (path === '/recovery/configure') {
        server.config = body as typeof server.config;
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
      if (path === '/recovery/keys') {
        if (body === undefined) return { keys: server.keys, cursor: null };
        server.keys.push(body);
        return { success: true };
      }
      throw new Error(`Unexpected request ${path}`);
    },
  },
}));

vi.mock('./crypto.service', () => ({
  getActiveDevice: () => mocks.owner,
  signDevicePayload: async () => 'signature',
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

import { backupRawHistoryKey, createRecoveryPlan, enableHistoryRecovery, restoreHistory } from './recovery.service';

const credentialId = 'YWxwYXJ0cy10ZXN0LWNyZWRlbnRpYWw';
const channelId = '22222222-2222-4222-8222-222222222222';
const passkeySecret = crypto.getRandomValues(new Uint8Array(32));
const keepsSecret = async () => ({
  id: credentialId,
  getClientExtensionResults: () => ({ prf: { results: { first: passkeySecret.slice().buffer } } }),
});
const cannotKeepSecret = async () => ({ id: credentialId, getClientExtensionResults: () => ({}) });
const envelope = (plan: { encryptedSecret: string }) => JSON.parse(plan.encryptedSecret);

beforeEach(() => {
  mocks.storage.clear();
  mocks.server.passkeys = [];
  mocks.server.config = null;
  mocks.server.keys = [];
  mocks.restored = [];
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
    await expect(restoreHistory()).rejects.toThrow('INVALID_PASSKEY_WRAP');
    expect(await restoreHistory(plan.code)).toBe(1);
    expect(mocks.restored).toEqual([[channelId, 1, key]]);
  });

  it('restores a plan that includes a passkey with the passkey alone', async () => {
    mocks.server.passkeys = [{ id: credentialId }];
    const plan = await createRecoveryPlan();
    const key = await turnOnWithOneKey(plan);
    expect(await restoreHistory()).toBe(1);
    expect(mocks.restored).toEqual([[channelId, 1, key]]);
  });
});
