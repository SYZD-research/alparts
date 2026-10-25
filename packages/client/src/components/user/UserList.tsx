import { useWorkspaceStore } from '../../stores/workspace.store';
import { usePresenceStore } from '../../stores/presence.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import type { WorkspaceMember } from '@alparts/shared';
import { partitionMembersByPresence } from '../../stores/presence-model';
import { UserAvatar } from './UserAvatar';
import { useT } from '../../i18n';

export function UserList() {
  const t = useT();
  const { members, activeWorkspaceId } = useWorkspaceStore();
  const { statuses } = usePresenceStore();
  const currentUserId = useAuthStore((state) => state.user?.id);
  const openDmComposer = useUiStore((state) => state.openDmComposer);
  const openMemberProfile = useUiStore((state) => state.openMemberProfile);

  const { online: onlineMembers, offline: offlineMembers } = partitionMembersByPresence(members, statuses);

  return (
    <div className="h-full w-full bg-panel overflow-y-auto">
      <div className="px-2 pb-3 pt-4">
        {/* Online members */}
        {onlineMembers.length > 0 && (
          <div className="mb-4">
            <h3 className="mb-1 px-2 text-xs font-medium text-muted">
              {t('オンライン — {count}', { count: onlineMembers.length })}
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
            <h3 className="mb-1 px-2 text-xs font-medium text-muted">
              {t('オフライン — {count}', { count: offlineMembers.length })}
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
  const t = useT();
  const statusColor = {
    online: 'bg-success',
    idle: 'bg-warning',
    dnd: 'bg-danger',
    offline: 'bg-muted',
  }[status] || 'bg-muted';

  return (
    <div className="group flex items-center gap-3 rounded-lg px-2 py-1.5 transition-colors hover:bg-hover">
      <button type="button" onClick={onOpenProfile} className="flex min-w-0 flex-1 items-center gap-3 text-left" aria-label={t('{name}のプロフィールを表示', { name: member.user?.displayName || t('不明なユーザー') })}>
        <div className="relative">
          <UserAvatar displayName={member.user?.displayName || '?'} avatarUrl={member.user?.avatarUrl} hidden={member.profileFlagged} size="sm" />
          <div className={`absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full ring-2 ring-panel group-hover:ring-hover ${statusColor}`} />
        </div>
        <div className="min-w-0">
          <div className={`truncate text-sm ${status === 'offline' ? 'text-muted' : 'font-medium text-ink'}`}>
            {member.user?.displayName || t('不明なユーザー')}
          </div>
          {member.roles?.length > 0 && (
            <div className="text-xs text-muted truncate">
              {member.roles[0].name}
            </div>
          )}
        </div>
      </button>
      {canDm && (
        <button type="button" onClick={onDm} className="ml-auto shrink-0 rounded-md border border-line px-2 py-0.5 text-xs text-ink-soft md:opacity-0 hover:bg-canvas hover:text-ink-strong group-hover:opacity-100 focus:opacity-100" aria-label={t('{name}とDM', { name: member.user.displayName })}>
          DM
        </button>
      )}
    </div>
  );
}
