import { describe, expect, it } from 'vitest';
import {
  applyMentionCompletion,
  extractMentionedUserIds,
  filterMentionMembers,
  findActiveMentionQuery,
  messageMentionsCurrentUser,
  splitMentionText,
  type MentionMember,
} from './mention-model';

const members: MentionMember[] = [
  { userId: 'user-alice', displayName: 'Alice' },
  { userId: 'user-bob', displayName: 'Bob Builder' },
];

describe('mention model', () => {
  it('opens completion as soon as @ is typed and replaces the active query', () => {
    const active = findActiveMentionQuery('hello @', 7);
    expect(active).toEqual({ start: 6, end: 7, query: '' });
    expect(filterMentionMembers(members, '')).toHaveLength(2);
    expect(applyMentionCompletion('hello @', active!, members[1])).toEqual({
      content: 'hello @Bob Builder ',
      caret: 19,
    });
  });

  it('does not treat the @ inside an email address as a completion query', () => {
    expect(findActiveMentionQuery('alice@example', 13)).toBeNull();
    expect(findActiveMentionQuery('@later', 0)).toBeNull();
  });

  it('recognizes member names and canonical ids without partial-name false positives', () => {
    const segments = splitMentionText('@Alice and <@user-bob>, not @AliceCo', members, 'user-bob', false);
    expect(segments.filter((segment) => segment.kind === 'mention')).toEqual([
      expect.objectContaining({ value: '@Alice', targetsCurrentUser: false }),
      expect.objectContaining({ value: '@Bob Builder', targetsCurrentUser: true }),
    ]);
  });

  it('only treats an authenticated broadcast marker as targeting the current user', () => {
    expect(messageMentionsCurrentUser('@everyone', members, 'user-alice', false)).toBe(false);
    expect(messageMentionsCurrentUser('@everyone', members, 'user-alice', true)).toBe(true);
  });

  it('extracts only canonical, unambiguous member recipients for notifications', () => {
    expect(extractMentionedUserIds('@Alice, <@user-bob>, @Alice', members)).toEqual([
      'user-alice',
      'user-bob',
    ]);
    expect(extractMentionedUserIds('@everyone and unknown@example.test', members)).toEqual([]);
    expect(extractMentionedUserIds('@Same', [
      { userId: 'first', displayName: 'Same' },
      { userId: 'second', displayName: 'Same' },
    ])).toEqual([]);
  });

  it('bounds direct notification recipients for one message', () => {
    const manyMembers = Array.from({ length: 55 }, (_, index) => ({
      userId: `user-${String(index).padStart(2, '0')}`,
      displayName: `Member ${index}`,
    }));
    const content = manyMembers.map((member) => `<@${member.userId}>`).join(' ');
    expect(extractMentionedUserIds(content, manyMembers)).toHaveLength(50);
  });
});
