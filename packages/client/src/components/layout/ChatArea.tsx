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
import { ForumView } from '../forum/ForumView';
import { useT } from '../../i18n';

export function ChatArea({ visible = true }: { visible?: boolean }) {
  const t = useT();
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
  const [freshStartError, setFreshStartError] = useState<string | null>(null);
  const [isStartingFresh, setIsStartingFresh] = useState(false);

  useEffect(() => {
    setShowFreshStart(false);
    setFreshStartError(null);
    setIsStartingFresh(false);
  }, [activeChannelId]);

  const closeFreshStart = () => {
    if (isStartingFresh) return;
    setShowFreshStart(false);
    setFreshStartError(null);
  };

  const confirmFreshStart = async () => {
    if (!activeChannelId || isStartingFresh) return;
    setIsStartingFresh(true);
    setFreshStartError(null);
    try {
      await startChannelWithoutHistory(activeChannelId);
      setShowFreshStart(false);
      } catch (error) {
      if (error instanceof ApiError && error.code === 'INVALID_CREDENTIALS') {
        setFreshStartError(t('パスワードが正しくありません。'));
      } else if (error instanceof ApiError && error.status === 403) {
        setFreshStartError(t('この操作を行う権限がありません。チャンネルの管理者へ依頼してください。'));
      } else if (
        (error instanceof ApiError && error.status === 409)
        || (error as { code?: unknown } | null)?.code === 'CHANNEL_GROUP_CHANGED'
      ) {
        setFreshStartError(t('チャンネルの状態が変わりました。閉じてから、もう一度お試しください。'));
      } else {
        setFreshStartError(t('新しいメッセージを開始できませんでした。もう一度お試しください。'));
      }
    } finally {
      setIsStartingFresh(false);
    }
  };

  useEffect(() => {
    if (activeChannelId) {
      const socket = getSocket();
      let disposed = false;
      let retryTimer: ReturnType<typeof setTimeout> | undefined;
      const join = () => {
        if (disposed) return;
        socket?.timeout(3000).emit('channel:join', activeChannelId, (error: Error | null, result?: { ok: boolean }) => {
          if (disposed) return;
          void loadMessages(activeChannelId);
          if (error || !result?.ok) retryTimer = setTimeout(join, 5000);
        });
      };
      void loadMessages(activeChannelId);
      join();
      return () => {
        disposed = true;
        clearTimeout(retryTimer);
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
      const pending = useMessageStore.getState().channelKeyPending[activeChannelId];
      // A device that may no longer ask to be added again checks rarely.
      if (!cancelled && pending) timer = setTimeout(() => { void retry(); }, pending.reason === 'unavailable' ? 60_000 : 5_000);
    };
    timer = setTimeout(() => { void retry(); }, 2_000);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeChannelId, channelKeyPending, retryChannelPreparation]);

  if (!activeChannelId) return null;

  const typingNames = Object.keys(typingUsers || {}).map((userId) => (
    members.find((member) => member.userId === userId)?.user.displayName || t('ユーザー')
  ));

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-discord-bg">
      <Dialog
        open={showFreshStart}
        onClose={closeFreshStart}
        title={t('新しいメッセージから開始しますか？')}
        description={t('以前のメッセージは削除されませんが、この端末では表示できないままになります。')}
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
            {t('チャンネルは新しいメッセージから再開されます。この操作は元に戻せません。')}
          </p>
          <p className="text-sm text-discord-text">
            {t('ほかのメンバーの端末は、それぞれがオンラインになるまで新しいメッセージを読めません。それまでに送られたメッセージは、その端末では読めないままになります。')}
          </p>
          {freshStartError && (
            <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
              {freshStartError}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={closeFreshStart} disabled={isStartingFresh} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">
              {t('キャンセル')}
            </button>
            <button type="submit" disabled={isStartingFresh} className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50">
              {isStartingFresh ? t('開始中…') : t('新しく開始')}
            </button>
          </div>
        </form>
      </Dialog>
      {/* Channel header */}
      <div className="chat-header h-12 shrink-0 px-4 flex items-center border-b border-discord-sidebar shadow-sm">
        <span className="text-discord-muted mr-2" aria-hidden="true">{dmConversation ? '@' : channel?.type === 'forum' ? '💬' : '#'}</span>
        <h3 className="truncate font-bold text-white">
          {dmConversation && currentUserId ? directMessageTitle(dmConversation, currentUserId) : channel?.name || t('チャンネル|single')}
        </h3>
        {channel?.topic && (
          <>
            <div className="hidden md:block w-px h-6 shrink-0 bg-discord-hover mx-3" />
            <span className="hidden md:block text-sm text-discord-muted truncate">{channel.topic}</span>
          </>
        )}
        <button type="button" onClick={openSavedMessages} className="ml-auto h-11 shrink-0 rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-white" aria-label={t('保存済みメッセージを開く')}>
          <span aria-hidden="true">🔖</span><span className="hidden md:inline"> {t('保存済み')}</span>
        </button>
      </div>

      {securityError ? (
        <div role="alert" className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-discord-red">
          <p>{t('このチャンネルを安全に表示できませんでした。')}</p>
          <button
            type="button"
            onClick={() => { void loadMessages(activeChannelId); }}
            className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white"
          >
            {t('再試行')}
          </button>
        </div>
      ) : channelRecoveryPending ? (
        <div role="status" className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-discord-muted">
          <p className="max-w-lg text-discord-text">
            {channelKeyPending?.reason === 'rejoining'
              ? t('この端末でこの会話を読み込めませんでした。参加し直しています。しばらくたっても読めない場合は、会話の管理者に連絡してください。')
              : t('この会話に参加しているほかの端末がオンラインになると、この端末でもメッセージを読み書きできるようになります。')}
          </p>
          {channelKeyPending?.freshStartAvailable && (
            <p className="max-w-lg text-sm">{t('待っても読めるようにならない場合は、過去のメッセージを使わずに会話を始め直せます。')}</p>
          )}
          <button
            type="button"
            disabled={isRetryingKey}
            onClick={() => {
              setIsRetryingKey(true);
              void retryChannelPreparation(activeChannelId).finally(() => setIsRetryingKey(false));
            }}
            className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white disabled:opacity-50"
          >
            {isRetryingKey ? t('再試行中…') : t('再試行')}
          </button>
          {channelKeyPending?.freshStartAvailable && (
            <button
              type="button"
              onClick={() => {
                setFreshStartError(null);
                setShowFreshStart(true);
              }}
              className="rounded px-3 py-2 text-sm text-discord-red underline hover:bg-discord-red/10"
            >
              {t('過去のメッセージを使わず開始')}
            </button>
          )}
        </div>
      ) : (
        <>
          {channel?.type === 'forum'
            ? <ForumView channelId={activeChannelId} sendDisabled={Boolean(channelKeyPending)} visible={visible} />
            : <MessageList channelId={activeChannelId} visible={visible} />}
          {channelKeyPending && (
            <div role="status" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded border border-discord-yellow/40 bg-discord-yellow/10 px-3 py-2 text-sm text-discord-yellow">
              <span>
                {channelKeyPending.reason === 'rejoining'
                  ? t('この端末でこの会話を読み込めませんでした。参加し直しています。しばらくたっても読めない場合は、会話の管理者に連絡してください。')
                  : channelKeyPending.reason === 'unavailable'
                    ? t('この端末ではこの会話を読み込めなくなりました。会話の管理者に連絡してください。')
                    : channelKeyPending.reason === 'genesis-waiting'
                      ? t('ほかのメンバーの端末がオンラインになると、メッセージを送信できるようになります。')
                      : t('この会話に参加しているほかの端末がオンラインになると、この端末でもメッセージを読み書きできるようになります。')}
              </span>
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
                  {isRetryingKey ? t('再試行中…') : t('再試行')}
                </button>
                {channelKeyPending.freshStartAvailable && (
                  <button
                    type="button"
                    onClick={() => {
                      setFreshStartError(null);
                      setShowFreshStart(true);
                    }}
                    className="rounded px-2 py-1 text-discord-red underline hover:bg-discord-red/10"
                  >
                    {t('過去を使わず開始')}
                  </button>
                )}
              </div>
            </div>
          )}
          {operationError && (
            <div role="alert" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
              <span>{t('操作を完了できませんでした。もう一度お試しください。')}</span>
              <button type="button" onClick={() => clearOperationError(activeChannelId)} className="underline">
                {t('閉じる')}
              </button>
            </div>
          )}
          {channel?.type !== 'forum' && (
            <>
              <div aria-live="polite" className="min-h-5 px-5 text-xs text-discord-muted">
                {typingNames.length > 0 ? t('{names} が入力中…', { names: typingNames.slice(0, 3).join(t('、')) }) : ''}
              </div>
              <MessageInput channelId={activeChannelId} sendDisabled={Boolean(channelKeyPending)} />
            </>
          )}
        </>
      )}
    </div>
  );
}
