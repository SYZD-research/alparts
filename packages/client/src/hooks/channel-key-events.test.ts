import { describe, expect, it, vi } from 'vitest';
import { handleChannelKeyStateEvent, handleChannelMemberAddedEvent } from './channel-key-events';

const channelId = '11111111-1111-4111-8111-111111111111';

function actions() {
  return {
    noteAuthorizationChange: vi.fn(),
    scheduleGroupMaintenance: vi.fn(),
    scheduleKeySync: vi.fn(),
  };
}

describe('channel key socket events', () => {
  it('prepares the group for a key state change without refreshing authorization views', () => {
    const spies = actions();
    handleChannelKeyStateEvent({ channelId }, spies);
    expect(spies.scheduleGroupMaintenance).toHaveBeenCalledOnce();
    expect(spies.scheduleKeySync).toHaveBeenCalledWith([channelId]);
    // Packages and commits in any channel the user sees send this event; an
    // open permission editor or forum list must not start over each time.
    expect(spies.noteAuthorizationChange).not.toHaveBeenCalled();
  });

  it('refreshes authorization views when a member is added', () => {
    const spies = actions();
    handleChannelMemberAddedEvent({ channelId, userId: 'u' }, spies);
    expect(spies.noteAuthorizationChange).toHaveBeenCalledOnce();
    expect(spies.scheduleKeySync).toHaveBeenCalledWith([channelId]);
  });

  it('ignores events without a channel', () => {
    const spies = actions();
    handleChannelKeyStateEvent(null, spies);
    handleChannelMemberAddedEvent({ channelId: 1 }, spies);
    expect(Object.values(spies).every((spy) => spy.mock.calls.length === 0)).toBe(true);
  });
});
