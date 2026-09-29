import type { UserStatusType, WorkspaceMember } from '@alparts/shared';

/** Live presence events win; otherwise the status loaded with the member list. */
export function memberStatus(member: WorkspaceMember, statuses: Record<string, UserStatusType>): UserStatusType {
  return statuses[member.userId] ?? member.user.status ?? 'offline';
}

/** Every member appears in exactly one list. */
export function partitionMembersByPresence(members: WorkspaceMember[], statuses: Record<string, UserStatusType>) {
  const online: Array<{ member: WorkspaceMember; status: UserStatusType }> = [];
  const offline: Array<{ member: WorkspaceMember; status: UserStatusType }> = [];
  for (const member of members) {
    const status = memberStatus(member, statuses);
    (status === 'offline' ? offline : online).push({ member, status });
  }
  return { online, offline };
}
