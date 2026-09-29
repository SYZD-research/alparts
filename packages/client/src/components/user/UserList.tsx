import { useWorkspaceStore } from '../../stores/workspace.store';
import { usePresenceStore } from '../../stores/presence.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import type { WorkspaceMember } from '@alparts/shared';
import { partitionMembersByPresence } from '../../stores/presence-model';
import { UserAvatar } from './UserAvatar';

export function UserList() {
  const { members, activeWorkspaceId } = useWorkspaceStore();
  const { statuses } = usePresenceStore();
  const currentUserId = useAuthStore((state) => state.user?.id);
  const openDmComposer = useUiStore((state) => state.openDmComposer);
  const openMemberProfile = useUiStore((state) => state.openMemberProfile);

  const { online: onlineMembers, offline: offlineMembers } = partitionMembersByPresence(members, statuses);

  return (
    <div className="h-full w-full bg-discord-sidebar overflow-y-auto">
      <div className="px-4 pt-6">
        {/* Online members */}
        {onlineMembers.length > 0 && (
          <div className="mb-4">
            <h3 className="text-xs font-bold text-discord-muted uppercase tracking-wide px-2 mb-2">
              オンライン — {onlineMembers.length}
            </h3>
            {onlineMembers.map(({ member, status }) => (
              <MemberItem
                key={member.userId}
                member={member}
                status={status}
                canDm={Boolean(activeWorkspaceId && member.userId !== currentUserId)}
                onDm={() => { if (activeWorkspaceId) openDmComposer(activeWorkspaceId, [member.userId]); }}
                onOpenProfile={() => { if (activeWorkspaceId) openMemberProfile(activeWorkspaceId, member.userId); }}
              />
            ))}
          </div>
        )}

        {/* Offline members */}
        {offlineMembers.length > 0 && (
          <div className="mb-4">
            <h3 className="text-xs font-bold text-discord-muted uppercase tracking-wide px-2 mb-2">
              オフライン — {offlineMembers.length}
            </h3>
            {offlineMembers.map(({ member }) => (
              <MemberItem
                key={member.userId}
                member={member}
                status="offline"
                canDm={Boolean(activeWorkspaceId && member.userId !== currentUserId)}
                onDm={() => { if (activeWorkspaceId) openDmComposer(activeWorkspaceId, [member.userId]); }}
                onOpenProfile={() => { if (activeWorkspaceId) openMemberProfile(activeWorkspaceId, member.userId); }}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function MemberItem({ member, status, canDm, onDm, onOpenProfile }: {
  member: WorkspaceMember;
  status: string;
  canDm: boolean;
  onDm: () => void;
  onOpenProfile: () => void;
}) {
  const statusColor = {
    online: 'bg-discord-green',
    idle: 'bg-discord-yellow',
    dnd: 'bg-discord-red',
    offline: 'bg-discord-muted',
  }[status] || 'bg-discord-muted';

  return (
    <div className="group flex items-center gap-3 px-2 py-1.5 rounded hover:bg-discord-hover">
      <button type="button" onClick={onOpenProfile} className="flex min-w-0 flex-1 items-center gap-3 text-left" aria-label={`${member.user?.displayName || '不明なユーザー'}のプロフィールを表示`}>
        <div className="relative">
          <UserAvatar displayName={member.user?.displayName || '?'} avatarUrl={member.user?.avatarUrl} hidden={member.profileFlagged} size="sm" />
          <div className={`absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full border-2 border-discord-sidebar ${statusColor}`} />
        </div>
        <div className="min-w-0">
          <div className={`text-sm truncate ${status === 'offline' ? 'text-discord-muted' : 'text-discord-text'}`}>
            {member.user?.displayName || '不明なユーザー'}
          </div>
          {member.roles?.length > 0 && (
            <div className="text-xs text-discord-muted truncate">
              {member.roles[0].name}
            </div>
          )}
        </div>
      </button>
      {canDm && (
        <button type="button" onClick={onDm} className="ml-auto shrink-0 rounded px-2 py-1 text-xs text-discord-muted md:opacity-0 hover:bg-discord-bg hover:text-white group-hover:opacity-100 focus:opacity-100" aria-label={`${member.user.displayName}とDM`}>
          DM
        </button>
      )}
    </div>
  );
}
