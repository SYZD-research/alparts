import type { AttentionNotificationKind } from '@alparts/shared';
import { useAttentionStore } from '../../stores/attention.store';
import { useChannelStore } from '../../stores/channel.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useUiStore } from '../../stores/ui.store';

export function AttentionNotifications() {
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
    if (channel) useChannelStore.getState().setActiveChannel(channel.id);
    if (kind === 'profile-appeal') useUiStore.getState().openWorkspaceManager();
    dismissKind(kind);
  };

  if (groups.length === 0) return null;
  return (
    <aside aria-label="新着通知" aria-live="polite" className="fixed right-4 top-4 z-50 w-72 space-y-2">
      {groups.map(({ kind, items: groupedItems }) => (
        <div key={kind} role="status" className="rounded-lg border border-discord-hover bg-discord-sidebar p-3 text-sm text-discord-text shadow-2xl">
          <div className="flex items-start gap-2">
            <button type="button" onClick={() => { void openLatest(kind); }} className="min-w-0 flex-1 text-left font-medium hover:underline">
              {kind === 'profile-appeal'
                ? `プロフィールの警告について、解除の依頼があります（${groupedItems.length}件）`
                : kind === 'channel-restarted'
                  ? `メンバーが新しく開始したため、以前のメッセージを表示できなくなったチャンネルがあります（${groupedItems.length}件）`
                  : kind === 'reply'
                    ? `${groupedItems.length}件の返信があります`
                    : `${groupedItems.length}件のメンションがあります`}
            </button>
            <button type="button" onClick={() => dismissKind(kind)} aria-label="通知を閉じる" className="rounded px-1 text-discord-muted hover:bg-discord-hover hover:text-white">×</button>
          </div>
        </div>
      ))}
    </aside>
  );
}
