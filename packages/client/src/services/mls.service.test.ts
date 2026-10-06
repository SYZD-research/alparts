import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./api', () => ({ api: { securityRequest: vi.fn() } }));
vi.mock('./crypto.service', () => ({
  getActiveDevice: () => ({ userId: 'account', deviceId: 'device' }),
  signDevicePayload: vi.fn(),
  verifyDevicePayload: vi.fn(),
}));
vi.mock('./directory.service', () => ({
  verifiedDirectory: vi.fn(),
  verifyDirectoryDevices: vi.fn(),
}));
vi.mock('./security-storage', async (original) => ({
  ...(await original<typeof import('./security-storage')>()),
  readSecurityState: vi.fn(),
}));
import { api } from './api';
import { channelKeyScopes } from './channel-key-scope';
import { readSecurityState, toBase64 } from './security-storage';
import { deriveMlsDelivery, nonMlsDeliveryAllowed } from './mls.service';

const channel = '11111111-1111-4111-8111-111111111111';
const transcript = 'a'.repeat(64);
const raw = new Uint8Array(32).fill(42);
function local(pinned: { version: number; transcript: string } | null) {
  vi.mocked(readSecurityState).mockImplementation(async (_owner, name) =>
    name.startsWith('mls-head:') ? pinned : { raw: toBase64(raw), transcript },
  );
}
beforeEach(() => {
  vi.stubGlobal('navigator', {
    locks: { request: (_name: string, run: () => unknown) => run() },
  });
  vi.mocked(api.securityRequest).mockRejectedValue(new Error('network verification required'));
  channelKeyScopes.reset();
});
afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('authenticated MLS archive and checkpoint reuse', () => {
  it('reuses an already activated exact transcript without refetching immutable proofs', async () => {
    local({ version: 2, transcript });
    expect(await deriveMlsDelivery(channel, 2, transcript, 'active')).toEqual(raw);
    expect(api.securityRequest).not.toHaveBeenCalled();
  });
  it('does not promote a pending local record without verifying its activation', async () => {
    local(null);
    await expect(deriveMlsDelivery(channel, 2, transcript, 'active')).rejects.toThrow(
      'network verification required',
    );
    expect(api.securityRequest).toHaveBeenCalledOnce();
  });
  it('rejects a substituted transcript and an active epoch older than the pinned head', async () => {
    local({ version: 2, transcript });
    await expect(deriveMlsDelivery(channel, 2, 'b'.repeat(64), 'active')).rejects.toThrow(
      'INVALID_MLS_TRANSCRIPT',
    );
    local({ version: 3, transcript: 'c'.repeat(64) });
    await expect(deriveMlsDelivery(channel, 2, transcript, 'active')).rejects.toThrow(
      'INVALID_MLS_TRANSCRIPT',
    );
    expect(api.securityRequest).not.toHaveBeenCalled();
  });
  it('keeps a verified retired archive readable without weakening channel revocation', async () => {
    local({ version: 3, transcript: 'c'.repeat(64) });
    expect(await deriveMlsDelivery(channel, 2, transcript, 'retired')).toEqual(raw);
    channelKeyScopes.invalidate(channel);
    await expect(deriveMlsDelivery(channel, 2, transcript, 'retired')).rejects.toThrow();
  });
});

describe('channels already on MLS (SEC-01)', () => {
  it('refuses a non-MLS key for the pinned version or later, but keeps older history', () => {
    expect(nonMlsDeliveryAllowed(null, 7)).toBe(true);
    expect(nonMlsDeliveryAllowed(5, 4)).toBe(true);
    expect(nonMlsDeliveryAllowed(5, 5)).toBe(false);
    expect(nonMlsDeliveryAllowed(5, 6)).toBe(false);
  });
});
