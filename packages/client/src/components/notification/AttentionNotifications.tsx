import type { AttentionNotificationKind } from '@alparts/shared';
import { useAttentionStore } from '../../stores/attention.store';
import { useChannelStore } from '../../stores/channel.store';
import { useForumStore } from '../../stores/forum.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useUiStore } from '../../stores/ui.store';
import { Icon } from '../ui/Icon';
import { useT } from '../../i18n';

export function AttentionNotifications() {
  const t = useT();
  const items = useAttentionStore((state) => state.items);
  const dismissKind = useAttentionStore((state) => state.dismissKind);
  const setActiveWorkspace = useWorkspaceStore((state) => state.setActiveWorkspace);
  const groups = (['profile-appeal', 'channel-restarted', 'reply', 'mention'] as AttentionNotificationKind[])
    .map((kind) => ({ kind, items: items.filter((item) => item.kind === kind) }))
    .filter((group) => group.items.length > 0);

  const openLatest = async (kind: AttentionNotificationKind) => {
    const latest = [...useAttentionStore.getState().items].reverse().find((item) => item.kind === kind);
    if (!latest) return;
    const workspaceState = useWorkspaceStore.getState();
    if (!workspaceState.workspaces.some((workspace) => workspace.id === latest.workspaceId)) {
      dismissKind(kind);
      return;
    }
    if (workspaceState.activeWorkspaceId !== latest.workspaceId) {
      await setActiveWorkspace(latest.workspaceId);
    }
    const channel = useChannelStore.getState().channels.find((candidate) => (
      candidate.id === latest.channelId && candidate.type !== 'voice'
    ));
    if (channel) {
      useChannelStore.getState().setActiveChannel(channel.id);
      if (channel.type === 'forum' && latest.postId) void useForumStore.getState().openPost(channel.id, latest.postId);
    }
    if (kind === 'profile-appeal') useUiStore.getState().openWorkspaceManager();
    dismissKind(kind);
  };

  if (groups.length === 0) return null;
  return (
    <aside aria-label={t('新着通知')} aria-live="polite" className="fixed right-4 top-4 z-50 w-72 space-y-2">
      {groups.map(({ kind, items: groupedItems }) => (
        <div key={kind} role="status" className="rounded-xl border border-line bg-raised p-3 text-sm text-ink shadow-2xl shadow-black/40">
          <div className="flex items-start gap-2">
            <button type="button" onClick={() => { void openLatest(kind); }} className="min-w-0 flex-1 text-left font-medium hover:underline">
              {kind === 'profile-appeal'
                ? t('プロフィールの警告について、解除の依頼があります（{count}件）', { count: groupedItems.length })
                : kind === 'channel-restarted'
                  ? t('メンバーが新しく開始したため、以前のメッセージを表示できなくなったチャンネルがあります（{count}件）', { count: groupedItems.length })
                  : kind === 'reply'
                    ? t('{count}件の返信があります', { count: groupedItems.length })
                    : t('{count}件のメンションがあります', { count: groupedItems.length })}
            </button>
            <button type="button" onClick={() => dismissKind(kind)} aria-label={t('通知を閉じる')} className="-m-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-muted hover:bg-hover hover:text-ink-strong"><Icon name="close" size={16} /></button>
          </div>
        </div>
      ))}
    </aside>
  );
}
