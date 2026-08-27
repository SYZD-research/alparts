import { describe, expect, it } from 'vitest';
import { ChannelKeyScopeGuard } from './channel-key-scope';

const channelId = '33333333-3333-4333-8333-333333333333';

describe('channel key authorization scope', () => {
  it('rejects late work and new work after revocation', () => {
    const guard = new ChannelKeyScopeGuard();
    const startedBeforeRevocation = guard.capture(channelId);

    guard.invalidate(channelId);

    expect(guard.isCurrent(startedBeforeRevocation)).toBe(false);
    expect(() => guard.assertCurrent(startedBeforeRevocation)).toThrow('scope changed');
    expect(() => guard.capture(channelId)).toThrow('scope is revoked');
  });

  it('only restores a scope after an explicit authorized refresh', () => {
    const guard = new ChannelKeyScopeGuard();
    const stale = guard.capture(channelId);
    guard.invalidate(channelId);
    guard.restore(channelId);
    const restored = guard.capture(channelId);

    expect(guard.isCurrent(stale)).toBe(false);
    expect(guard.isCurrent(restored)).toBe(true);
  });

  it('invalidates every in-flight token when the authenticated device changes', () => {
    const guard = new ChannelKeyScopeGuard();
    const oldDeviceWork = guard.capture(channelId);
    guard.reset();

    expect(guard.isCurrent(oldDeviceWork)).toBe(false);
    expect(guard.isCurrent(guard.capture(channelId))).toBe(true);
  });
});
