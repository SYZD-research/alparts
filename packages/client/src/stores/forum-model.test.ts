import { describe, expect, it } from 'vitest';
import { compareForumPosts, isForumPostUnread, placeForumPost, type ForumPostBroadcastState } from './forum-model';

function post(postId: string, overrides: Partial<ForumPostBroadcastState> = {}): ForumPostBroadcastState {
  return {
    postId,
    channelId: 'c',
    authorId: 'author',
    createdAt: '2026-10-01T00:00:00.000Z',
    lastActivityAt: '2026-10-01T00:00:00.000Z',
    replyCount: 0,
    locked: false,
    resolved: false,
    tagIds: [],
    isPinned: false,
    ...overrides,
  };
}

describe('forum list model', () => {
  it('orders pinned posts first, then by the chosen time', () => {
    const pinned = post('a', { isPinned: true, lastActivityAt: '2026-01-01T00:00:00.000Z' });
    const recent = post('b', { lastActivityAt: '2026-10-02T00:00:00.000Z' });
    const older = post('c', { createdAt: '2026-10-03T00:00:00.000Z' });
    expect([older, recent, pinned].sort((l, r) => compareForumPosts('activity', l, r)).map((p) => p.postId)).toEqual(['a', 'b', 'c']);
    expect([recent, older, pinned].sort((l, r) => compareForumPosts('created', l, r)).map((p) => p.postId)).toEqual(['a', 'c', 'b']);
  });

  it('moves an active post to the top and respects the tag filter', () => {
    const states = { a: post('a', { lastActivityAt: '2026-10-03T00:00:00.000Z' }), b: post('b', { lastActivityAt: '2026-10-02T00:00:00.000Z' }) };
    const bumped = post('b', { lastActivityAt: '2026-10-04T00:00:00.000Z' });
    expect(placeForumPost(['a', 'b'], states, bumped, 'activity', null, false)).toEqual(['b', 'a']);
    expect(placeForumPost(['a', 'b'], states, bumped, 'activity', 'tag', false)).toEqual(['a']);
    expect(placeForumPost(['a', 'b'], states, { ...bumped, tagIds: ['tag'] }, 'activity', 'tag', false)).toEqual(['b', 'a']);
  });

  it('does not insert an unknown post beyond the loaded page', () => {
    const states = { a: post('a', { lastActivityAt: '2026-10-03T00:00:00.000Z' }) };
    const old = post('z', { lastActivityAt: '2026-09-01T00:00:00.000Z' });
    expect(placeForumPost(['a'], states, old, 'activity', null, true)).toEqual(['a']);
    expect(placeForumPost(['a'], states, old, 'activity', null, false)).toEqual(['a', 'z']);
  });

  it('marks other people\'s unseen posts and newer activity as unread', () => {
    const state = post('a', { lastActivityAt: '2026-10-02T00:00:00.000Z' });
    expect(isForumPostUnread(state, undefined, 'me')).toBe(true);
    expect(isForumPostUnread(state, undefined, 'author')).toBe(false);
    expect(isForumPostUnread(state, '2026-10-01T00:00:00.000Z', 'me')).toBe(true);
    expect(isForumPostUnread(state, '2026-10-02T00:00:00.000Z', 'me')).toBe(false);
  });
});
