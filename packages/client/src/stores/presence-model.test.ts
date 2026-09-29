import { describe, expect, it } from 'vitest';
import type { UserStatusType, WorkspaceMember } from '@alparts/shared';
import { memberStatus, partitionMembersByPresence } from './presence-model';

const member = (userId: string, status: UserStatusType) => ({
  id: `m-${userId}`,
  workspaceId: 'w',
  userId,
  user: { id: userId, displayName: userId, avatarUrl: null, status, createdAt: '2026-09-29T00:00:00.000Z' },
  roles: [],
  joinedAt: '2026-09-29T00:00:00.000Z',
}) as unknown as WorkspaceMember;

describe('member presence', () => {
  it('lists every member exactly once', () => {
    const members = [member('a', 'online'), member('b', 'offline'), member('c', 'idle'), member('d', 'offline')];
    // "d" has no live event yet; "b" went online after the list was loaded.
    const { online, offline } = partitionMembersByPresence(members, { b: 'online' });
    expect(online.map((entry) => entry.member.userId)).toEqual(['a', 'b', 'c']);
    expect(offline.map((entry) => entry.member.userId)).toEqual(['d']);
    expect(online.length + offline.length).toBe(members.length);
  });

  it('prefers live events over the loaded status and never guesses online', () => {
    expect(memberStatus(member('a', 'online'), { a: 'offline' })).toBe('offline');
    expect(memberStatus(member('a', 'offline'), {})).toBe('offline');
    expect(memberStatus(member('a', 'dnd'), {})).toBe('dnd');
  });
});
