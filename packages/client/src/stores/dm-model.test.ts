import { describe, expect, it } from 'vitest';
import type { DirectMessageConversation, DirectMessageMember } from '../services/api';
import { directMessageTitle, findReusableOneToOneDm } from './dm-model';

function member(id: string, displayName = id): DirectMessageMember {
  return { id, displayName, avatarUrl: null, status: 'online', createdAt: '2026-01-01T00:00:00.000Z' };
}

function dm(id: string, members: DirectMessageMember[]): DirectMessageConversation {
  return { id, channelId: id, workspaceId: 'workspace-1', createdAt: '2026-01-01T00:00:00.000Z', members };
}

describe('direct-message model', () => {
  it('reuses only an exact one-to-one conversation regardless of member order', () => {
    const direct = dm('direct', [member('bob', 'Bob'), member('alice', 'Alice')]);
    const group = dm('group', [member('alice'), member('bob'), member('charlie')]);

    expect(findReusableOneToOneDm([group, direct], 'alice', 'bob')?.id).toBe('direct');
    expect(findReusableOneToOneDm([group], 'alice', 'bob')).toBeNull();
  });

  it('builds a title without exposing the current member name', () => {
    expect(directMessageTitle(dm('group', [member('alice', 'Alice'), member('bob', 'Bob'), member('charlie', 'Charlie')]), 'alice'))
      .toBe('Bob、Charlie');
  });
});
