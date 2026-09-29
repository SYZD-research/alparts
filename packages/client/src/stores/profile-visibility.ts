import type { WorkspaceMember } from '@alparts/shared';

/** Users warned in the active workspace, including former members. Null until loaded or when loading failed. */
export interface WarnedUsers {
  ids: ReadonlySet<string>;
  complete: boolean;
}

/**
 * Whether a user's picture stays hidden in this workspace. Current members
 * carry their own mark. For anyone else (a former member whose messages
 * remain) the workspace's warned list decides; while that list is missing or
 * was cut short, their picture stays hidden.
 */
export function isPictureHidden(userId: string, members: readonly WorkspaceMember[], warned: WarnedUsers | null): boolean {
  const member = members.find((candidate) => candidate.userId === userId);
  if (member) return Boolean(member.profileFlagged);
  if (!warned || !warned.complete) return true;
  return warned.ids.has(userId);
}
