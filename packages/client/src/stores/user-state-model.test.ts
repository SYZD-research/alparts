import { describe, expect, it } from 'vitest';
import {
  defaultChannelReadState,
  latestReadableMessageId,
  mergeChannelPreference,
  readAdvanceDecision,
  scanLoadedMentionUnread,
  sortBookmarks,
} from './user-state-model';

const messages = [
  { id: '00000000-0000-4000-8000-000000000001', type: 'message', createdAt: '2026-01-01T00:00:00.000Z' },
  { id: '00000000-0000-4000-8000-000000000002', type: 'message', createdAt: '2026-01-01T00:00:00.000Z' },
  { id: '00000000-0000-4000-8000-000000000003', type: 'message', createdAt: '2026-01-01T00:00:01.000Z' },
];

describe('user state model', () => {
  it('rejects known read-position rollback and uses binary id order for timestamp ties', () => {
    expect(readAdvanceDecision(messages[1].id, messages[0].id, messages)).toBe('behind');
    expect(readAdvanceDecision(messages[0].id, messages[1].id, messages)).toBe('advance');
    expect(readAdvanceDecision(messages[1].id, 'not-loaded', messages)).toBe('unknown');
  });

  it('merges a preference without losing read state', () => {
    const current = { ...defaultChannelReadState('channel'), lastReadMessageId: 'message', unreadCount: 4 };
    expect(mergeChannelPreference(current, {
      channelId: 'channel',
      favorite: true,
      muted: true,
      hidden: false,
      notificationLevel: 'mentions',
      updatedAt: '2026-01-01T00:00:00.000Z',
    })).toMatchObject({ favorite: true, muted: true, lastReadMessageId: 'message', unreadCount: 4 });
  });

  it('does not use a deleted logical message as the read boundary', () => {
    expect(latestReadableMessageId([
      messages[0],
      { ...messages[1], type: 'delete' },
      { ...messages[2], type: 'edit' },
    ])).toBe(messages[2].id);
    expect(latestReadableMessageId([{ ...messages[2], type: 'delete' }])).toBeNull();
  });

  it('counts only locally decrypted mentions after a known boundary', () => {
    const scan = scanLoadedMentionUnread([
      { ...messages[0], authorId: 'other', content: '@Alice old' },
      { ...messages[1], authorId: 'other', content: 'hello <@user-1>' },
      { ...messages[2], authorId: 'user-1', content: '@Alice self' },
    ], { id: 'user-1', displayName: 'Alice' }, messages[0].id, true);
    expect(scan).toEqual({ count: 1, scannedMessages: 2, boundaryKnown: true, completeForUnreadWindow: true });
  });

  it('does not fabricate an unread mention count when the boundary is not loaded', () => {
    const scan = scanLoadedMentionUnread([
      { ...messages[2], authorId: 'other', content: '@Alice maybe unread' },
    ], { id: 'user-1', displayName: 'Alice' }, 'older-not-loaded', true);
    expect(scan).toMatchObject({ count: 0, boundaryKnown: false, completeForUnreadWindow: false });
  });

  it('does not treat unsigned broadcast words as notification mentions', () => {
    const scan = scanLoadedMentionUnread([
      { ...messages[1], authorId: 'other', content: '@everyone deployment' },
      { ...messages[2], authorId: 'other', content: '@here now' },
    ], { id: 'user-1', displayName: 'Alice' }, null, false);
    expect(scan.count).toBe(0);
  });

  it('does not count a longer unknown @name as a mention of a prefix-matching member', () => {
    const scan = scanLoadedMentionUnread([
      { ...messages[1], authorId: 'other', content: '@AliceCo deployment' },
    ], { id: 'user-1', displayName: 'Alice' }, null, false);
    expect(scan.count).toBe(0);
  });

  it('counts an authenticated broadcast mention flag', () => {
    const scan = scanLoadedMentionUnread([
      { ...messages[1], authorId: 'other', content: '@everyone deployment', broadcastMention: true },
    ], { id: 'user-1', displayName: 'Alice' }, null, false);
    expect(scan.count).toBe(1);
  });

  it('sorts bookmarks newest-first deterministically', () => {
    const sorted = sortBookmarks([
      { messageId: 'a', channelId: 'channel', createdAt: '2026-01-01T00:00:00.000Z' },
      { messageId: 'b', channelId: 'channel', createdAt: '2026-01-02T00:00:00.000Z' },
    ]);
    expect(sorted.map((bookmark) => bookmark.messageId)).toEqual(['b', 'a']);
  });
});
