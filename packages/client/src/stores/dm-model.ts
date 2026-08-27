import type { DirectMessageConversation } from '../services/api';

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
}
export function findReusableOneToOneDm(
  conversations: DirectMessageConversation[],
  currentUserId: string,
  otherUserId: string,
): DirectMessageConversation | null {
  const expected = uniqueSorted([currentUserId, otherUserId]);
  return conversations.find((conversation) => {
    const actual = uniqueSorted(conversation.members.map((member) => member.id));
    return actual.length === 2 && actual[0] === expected[0] && actual[1] === expected[1];
  }) || null;
}

export function directMessageTitle(conversation: DirectMessageConversation, currentUserId: string): string {
  const names = conversation.members
    .filter((member) => member.id !== currentUserId)
    .map((member) => member.displayName);
  return names.length > 0 ? names.join('、') : '自分だけのDM';
}
