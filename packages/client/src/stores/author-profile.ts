import type { PublicUser, WorkspaceMember } from '@alparts/shared';

export interface AuthorProfile {
  displayName: string | null;
  avatarUrl: string | null;
}

const indexes = new WeakMap<readonly WorkspaceMember[], Map<string, WorkspaceMember>>();

function memberIndex(members: readonly WorkspaceMember[]): Map<string, WorkspaceMember> {
  let index = indexes.get(members);
  if (!index) {
    index = new Map(members.map((member) => [member.userId, member]));
    indexes.set(members, index);
  }
  return index;
}

/**
 * The name and picture to show for someone who wrote a message: the
 * workspace member list, which follows profile changes, else the copy the
 * message arrived with (a former member, or a list not loaded yet).
 */
export function currentAuthor(
  members: readonly WorkspaceMember[],
  userId: string | null | undefined,
  carried: Pick<PublicUser, 'displayName' | 'avatarUrl'> | null | undefined,
): AuthorProfile {
  const member = userId ? memberIndex(members).get(userId) : undefined;
  if (member) return { displayName: member.user.displayName, avatarUrl: member.user.avatarUrl };
  return { displayName: carried?.displayName ?? null, avatarUrl: carried?.avatarUrl ?? null };
}
