import { describe, expect, it } from 'vitest';
import { buildChannelStoragePrefix, isChannelStorageKeyForPrefix } from './crypto.service';

const userId = '11111111-1111-4111-8111-111111111111';
const deviceId = '22222222-2222-4222-8222-222222222222';
const channelId = '33333333-3333-4333-8333-333333333333';

describe('persisted channel key cleanup scope', () => {
  it('matches only exact user/device/channel keys with bounded positive versions', () => {
    const prefix = buildChannelStoragePrefix(userId, deviceId, channelId);
    expect(prefix).toBe(`channel:${userId}:${deviceId}:${channelId}:`);
    expect(isChannelStorageKeyForPrefix(`${prefix}1`, prefix)).toBe(true);
    expect(isChannelStorageKeyForPrefix(`${prefix}1000000`, prefix)).toBe(true);
    expect(isChannelStorageKeyForPrefix(`${prefix}0`, prefix)).toBe(false);
    expect(isChannelStorageKeyForPrefix(`${prefix}1:other`, prefix)).toBe(false);
    expect(isChannelStorageKeyForPrefix(`channel:${userId}:${deviceId}:${channelId}0:1`, prefix)).toBe(false);
    expect(isChannelStorageKeyForPrefix(`channel:${userId}:${deviceId}:44444444-4444-4444-8444-444444444444:1`, prefix)).toBe(false);
  });

  it('rejects malformed scope ids before opening a broad cursor range', () => {
    expect(() => buildChannelStoragePrefix(userId, deviceId, 'not-a-channel')).toThrow('scope is invalid');
  });
});
