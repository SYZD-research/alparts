import { useEffect, useState } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { usePresenceStore } from '../../stores/presence.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { MessageList } from '../message/MessageList';
import { MessageInput } from '../message/MessageInput';
import { getSocket } from '../../services/socket';
import { useDmStore } from '../../stores/dm.store';
import { useAuthStore } from '../../stores/auth.store';
import { directMessageTitle } from '../../stores/dm-model';
import { useUiStore } from '../../stores/ui.store';

export function ChatArea() {
  const activeChannelId = useChannelStore((state) => state.activeChannelId);
  const channel = useChannelStore((state) => state.channels.find((candidate) => candidate.id === state.activeChannelId));
  const loadMessages = useMessageStore((state) => state.loadMessages);
  const retryChannelPreparation = useMessageStore((state) => state.retryChannelPreparation);
  const securityError = useMessageStore((state) => activeChannelId ? state.securityErrors[activeChannelId] : null);
  const channelKeyPending = useMessageStore((state) => activeChannelId ? state.channelKeyPending[activeChannelId] : null);
  const channelRecoveryPending = useMessageStore((state) => activeChannelId ? state.channelRecoveryPending[activeChannelId] : false);
  const operationError = useMessageStore((state) => activeChannelId ? state.operationErrors[activeChannelId] : null);
  const clearOperationError = useMessageStore((state) => state.clearOperationError);
  const typingUsers = usePresenceStore((state) => activeChannelId ? state.typingUsers[activeChannelId] : undefined);
  const members = useWorkspaceStore((state) => state.members);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const currentUserId = useAuthStore((state) => state.user?.id);
  const dmConversation = useDmStore((state) => activeWorkspaceId && activeChannelId
    ? state.conversationsByWorkspace[activeWorkspaceId]?.find((conversation) => conversation.channelId === activeChannelId)
    : undefined);
  const openSavedMessages = useUiStore((state) => state.openSavedMessages);
  const [isRetryingKey, setIsRetryingKey] = useState(false);

  useEffect(() => {
    if (activeChannelId) {
      const socket = getSocket();
      socket?.emit('channel:join', activeChannelId, (result: { ok: boolean }) => {
        if (result.ok) void loadMessages(activeChannelId);
      });
      return () => {
        socket?.emit('channel:leave', activeChannelId);
      };
    }
  }, [activeChannelId, loadMessages]);

  useEffect(() => {
    if (!activeChannelId || !channelKeyPending) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const retry = async () => {
      await retryChannelPreparation(activeChannelId);
      if (!cancelled && useMessageStore.getState().channelKeyPending[activeChannelId]) {
        timer = setTimeout(() => { void retry(); }, 5_000);
      }
    };
    timer = setTimeout(() => { void retry(); }, 2_000);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeChannelId, channelKeyPending, retryChannelPreparation]);

  if (!activeChannelId) return null;

  const typingNames = Object.keys(typingUsers || {}).map((userId) => (
    members.find((member) => member.userId === userId)?.user.displayName || 'ユーザー'
  ));

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-discord-bg">
      {/* Channel header */}
      <div className="h-12 px-4 flex items-center border-b border-discord-sidebar shadow-sm">
        <span className="text-discord-muted mr-2">{dmConversation ? '@' : '#'}</span>
        <h3 className="font-bold text-white">
          {dmConversation && currentUserId ? directMessageTitle(dmConversation, currentUserId) : channel?.name || 'チャンネル'}
        </h3>
        {channel?.topic && (
          <>
            <div className="w-px h-6 bg-discord-hover mx-3" />
            <span className="text-sm text-discord-muted truncate">{channel.topic}</span>
          </>
        )}
        <button type="button" onClick={openSavedMessages} className="ml-auto shrink-0 rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-white" aria-label="保存済みメッセージを開く">
          🔖 保存済み
        </button>
      </div>

      {securityError ? (
        <div role="alert" className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-discord-red">
          <p>このチャンネルを安全に表示できませんでした。</p>
          <button
            type="button"
            onClick={() => { void loadMessages(activeChannelId); }}
            className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white"
          >
            再試行
          </button>
        </div>
      ) : channelRecoveryPending ? (
        <div role="status" className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-discord-muted">
          <p className="text-discord-text">この端末でメッセージを表示する準備をしています。</p>
          <p className="max-w-lg text-sm">以前使っていた端末でalpartsを開いたままにしてください。準備が終わると自動で表示されます。</p>
          <button
            type="button"
            disabled={isRetryingKey}
            onClick={() => {
              setIsRetryingKey(true);
              void retryChannelPreparation(activeChannelId).finally(() => setIsRetryingKey(false));
            }}
            className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white disabled:opacity-50"
          >
            {isRetryingKey ? '再試行中…' : '再試行'}
          </button>
        </div>
      ) : (
        <>
          <MessageList channelId={activeChannelId} />
          {channelKeyPending && (
            <div role="status" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded border border-discord-yellow/40 bg-discord-yellow/10 px-3 py-2 text-sm text-discord-yellow">
              <span>メッセージを送信できるよう準備しています。しばらくお待ちください。</span>
              <button
                type="button"
                disabled={isRetryingKey}
                onClick={() => {
                  setIsRetryingKey(true);
                  void retryChannelPreparation(activeChannelId).finally(() => setIsRetryingKey(false));
                }}
                className="shrink-0 rounded px-2 py-1 underline hover:bg-discord-hover disabled:opacity-50"
              >
                {isRetryingKey ? '再試行中…' : '再試行'}
              </button>
            </div>
          )}
          {operationError && (
            <div role="alert" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
              <span>操作を完了できませんでした。もう一度お試しください。</span>
              <button type="button" onClick={() => clearOperationError(activeChannelId)} className="underline">
                閉じる
              </button>
            </div>
          )}
          <div aria-live="polite" className="min-h-5 px-5 text-xs text-discord-muted">
            {typingNames.length > 0 ? `${typingNames.slice(0, 3).join('、')} が入力中…` : ''}
          </div>
          <MessageInput channelId={activeChannelId} sendDisabled={Boolean(channelKeyPending)} />
        </>
      )}
    </div>
  );
}
