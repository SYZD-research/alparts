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
import { ApiError } from '../../services/api';
import { Dialog } from '../ui/Dialog';

export function ChatArea() {
  const activeChannelId = useChannelStore((state) => state.activeChannelId);
  const channel = useChannelStore((state) => state.channels.find((candidate) => candidate.id === state.activeChannelId));
  const loadMessages = useMessageStore((state) => state.loadMessages);
  const retryChannelPreparation = useMessageStore((state) => state.retryChannelPreparation);
  const startChannelWithoutHistory = useMessageStore((state) => state.startChannelWithoutHistory);
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
  const [showFreshStart, setShowFreshStart] = useState(false);
  const [freshStartPassword, setFreshStartPassword] = useState('');
  const [freshStartError, setFreshStartError] = useState<string | null>(null);
  const [isStartingFresh, setIsStartingFresh] = useState(false);

  useEffect(() => {
    setShowFreshStart(false);
    setFreshStartPassword('');
    setFreshStartError(null);
    setIsStartingFresh(false);
  }, [activeChannelId]);

  const closeFreshStart = () => {
    if (isStartingFresh) return;
    setShowFreshStart(false);
    setFreshStartPassword('');
    setFreshStartError(null);
  };

  const confirmFreshStart = async () => {
    if (!activeChannelId || isStartingFresh || freshStartPassword.length === 0) return;
    setIsStartingFresh(true);
    setFreshStartError(null);
    try {
      await startChannelWithoutHistory(activeChannelId, freshStartPassword);
      setShowFreshStart(false);
      setFreshStartPassword('');
    } catch (error) {
      if (error instanceof ApiError && error.code === 'INVALID_CREDENTIALS') {
        setFreshStartError('パスワードが正しくありません。');
      } else if (error instanceof ApiError && error.status === 403) {
        setFreshStartError('この操作を行う権限がありません。チャンネルの管理者へ依頼してください。');
      } else if (error instanceof ApiError && error.status === 409) {
        setFreshStartError('チャンネルの状態が変わりました。閉じてから、もう一度お試しください。');
      } else {
        setFreshStartError('新しいメッセージを開始できませんでした。もう一度お試しください。');
      }
    } finally {
      setIsStartingFresh(false);
    }
  };

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
      <Dialog
        open={showFreshStart}
        onClose={closeFreshStart}
        title="新しいメッセージから開始しますか？"
        description="以前のメッセージは削除されませんが、この端末では表示できないままになります。"
        size="sm"
      >
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            void confirmFreshStart();
          }}
        >
          <p className="rounded border border-discord-red/60 bg-discord-red/10 p-3 text-sm text-discord-text">
            チャンネルは新しいメッセージから再開されます。この操作は元に戻せません。
          </p>
          <label className="block text-sm text-discord-text">
            パスワード
            <input
              autoFocus
              type="password"
              autoComplete="current-password"
              value={freshStartPassword}
              onChange={(event) => setFreshStartPassword(event.target.value)}
              disabled={isStartingFresh}
              className="mt-1 w-full rounded bg-discord-input px-3 py-2 text-white outline-none focus:ring-2 focus:ring-discord-accent disabled:opacity-50"
            />
          </label>
          {freshStartError && (
            <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
              {freshStartError}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={closeFreshStart} disabled={isStartingFresh} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">
              キャンセル
            </button>
            <button type="submit" disabled={isStartingFresh || freshStartPassword.length === 0} className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50">
              {isStartingFresh ? '開始中…' : '新しく開始'}
            </button>
          </div>
        </form>
      </Dialog>
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
          <button
            type="button"
            onClick={() => {
              setFreshStartError(null);
              setShowFreshStart(true);
            }}
            className="rounded px-3 py-2 text-sm text-discord-red underline hover:bg-discord-red/10"
          >
            過去のメッセージを使わず開始
          </button>
        </div>
      ) : (
        <>
          <MessageList channelId={activeChannelId} />
          {channelKeyPending && (
            <div role="status" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded border border-discord-yellow/40 bg-discord-yellow/10 px-3 py-2 text-sm text-discord-yellow">
              <span>メッセージを送信できるよう準備しています。しばらくお待ちください。</span>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  type="button"
                  disabled={isRetryingKey}
                  onClick={() => {
                    setIsRetryingKey(true);
                    void retryChannelPreparation(activeChannelId).finally(() => setIsRetryingKey(false));
                  }}
                  className="rounded px-2 py-1 underline hover:bg-discord-hover disabled:opacity-50"
                >
                  {isRetryingKey ? '再試行中…' : '再試行'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFreshStartError(null);
                    setShowFreshStart(true);
                  }}
                  className="rounded px-2 py-1 text-discord-red underline hover:bg-discord-red/10"
                >
                  過去を使わず開始
                </button>
              </div>
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
