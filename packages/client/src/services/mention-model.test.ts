import { describe, expect, it } from 'vitest';
import {
  applyMentionCompletion,
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
});
