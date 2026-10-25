import { describe, expect, it } from 'vitest';
import type { WorkspaceMember } from '@alparts/shared';
import { currentAuthor } from './author-profile';

function member(userId: string, displayName: string, avatarUrl: string | null = null): WorkspaceMember {
  return {
    id: `member-${userId}`,
    workspaceId: 'workspace',
    userId,
    user: { id: userId, displayName, avatarUrl, status: 'online', createdAt: '2026-10-01T00:00:00.000Z' },
    roles: [],
    joinedAt: '2026-10-01T00:00:00.000Z',
  };
}

describe('currentAuthor', () => {
  it('shows the name and picture a member has now, not the ones a message carried', () => {
    const members = [member('u1', 'Bea Renamed', '/api/profiles/u1/avatar/2')];
    expect(currentAuthor(members, 'u1', { displayName: 'Bea', avatarUrl: '/api/profiles/u1/avatar/1' }))
      .toEqual({ displayName: 'Bea Renamed', avatarUrl: '/api/profiles/u1/avatar/2' });
  });

  it('keeps what the message carried for someone who is not a member', () => {
    expect(currentAuthor([member('u1', 'Aki')], 'u2', { displayName: 'Former', avatarUrl: null }))
      .toEqual({ displayName: 'Former', avatarUrl: null });
    expect(currentAuthor([], undefined, undefined)).toEqual({ displayName: null, avatarUrl: null });
  });

  it('follows a member list that was replaced', () => {
    const before = [member('u1', 'Bea')];
    expect(currentAuthor(before, 'u1', null).displayName).toBe('Bea');
    const after = [member('u1', 'Bea Renamed')];
    expect(currentAuthor(after, 'u1', null).displayName).toBe('Bea Renamed');
  });
});
