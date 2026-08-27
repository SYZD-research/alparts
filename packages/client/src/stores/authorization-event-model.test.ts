import { describe, expect, it } from 'vitest';
import {
  MAX_REVOKED_CHANNEL_HINTS,
  parseChannelAuthorizationEvent,
  parseWorkspaceAccessRevokedEvent,
  parseWorkspaceAuthorizationRefresh,
} from './authorization-event-model';

const workspaceId = '11111111-1111-4111-8111-111111111111';
const channelId = '22222222-2222-4222-8222-222222222222';

describe('authorization socket payload validation', () => {
  it('deduplicates bounded, strictly valid workspace revoke hints', () => {
    expect(parseWorkspaceAccessRevokedEvent({
      workspaceId,
      membershipRemoved: true,
      channelIds: [channelId, channelId],
    })).toEqual({ workspaceId, membershipRemoved: true, channelIds: [channelId] });
  });

  it('always applies valid workspace removal while bounding untrusted hints', () => {
    expect(parseWorkspaceAccessRevokedEvent({ workspaceId, membershipRemoved: false, channelIds: [] })).toBeNull();
    expect(parseWorkspaceAccessRevokedEvent({ workspaceId, membershipRemoved: true, channelIds: ['bad'] }))
      .toEqual({ workspaceId, membershipRemoved: true, channelIds: [] });
    expect(parseWorkspaceAccessRevokedEvent({
      workspaceId,
      membershipRemoved: true,
      channelIds: Array.from({ length: MAX_REVOKED_CHANNEL_HINTS + 1 }, () => channelId),
    })).toEqual({ workspaceId, membershipRemoved: true, channelIds: [channelId] });
    expect(parseWorkspaceAccessRevokedEvent({ workspaceId, membershipRemoved: true, channelIds: null }))
      .toEqual({ workspaceId, membershipRemoved: true, channelIds: [] });
    expect(parseChannelAuthorizationEvent({ workspaceId, channelId: 'bad' })).toBeNull();
  });

  it('keeps permission refresh separate from membership removal', () => {
    expect(parseWorkspaceAuthorizationRefresh({ workspaceId, membershipRemoved: false })).toEqual({ workspaceId });
    expect(parseWorkspaceAuthorizationRefresh({ workspaceId, membershipRemoved: true })).toBeNull();
    expect(parseChannelAuthorizationEvent({ workspaceId, channelId })).toEqual({ workspaceId, channelId });
  });
});
