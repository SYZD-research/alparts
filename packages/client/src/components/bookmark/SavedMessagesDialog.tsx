import { useEffect, useState } from 'react';
import { api } from '../../services/api';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { useUiStore } from '../../stores/ui.store';
import { useUserStateStore } from '../../stores/user-state.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { Dialog } from '../ui/Dialog';
import { userFacingMessageText } from '../../services/message-display';
import { formatDateTime } from '../../stores/date-format';
import { useForumStore } from '../../stores/forum.store';
import { useT } from '../../i18n';

const HISTORY_PAGE_LIMIT = 20;

export function SavedMessagesDialog() {
  const t = useT();
  const open = useUiStore((state) => state.isSavedMessagesOpen);
  const close = useUiStore((state) => state.closeSavedMessages);
  const bookmarks = useUserStateStore((state) => state.bookmarks);
  const loading = useUserStateStore((state) => state.bookmarksLoading);
  const error = useUserStateStore((state) => state.bookmarkError);
  const savingByMessage = useUserStateStore((state) => state.bookmarkSavingByMessage);
  const loadBookmarks = useUserStateStore((state) => state.loadBookmarks);
  const toggleBookmark = useUserStateStore((state) => state.toggleBookmark);
  const clearBookmarkError = useUserStateStore((state) => state.clearBookmarkError);
  const channels = useChannelStore((state) => state.channels);
  const setActiveChannel = useChannelStore((state) => state.setActiveChannel);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const setActiveWorkspace = useWorkspaceStore((state) => state.setActiveWorkspace);
  const messagesByChannel = useMessageStore((state) => state.messagesByChannel);
  const loadMessageThroughHistory = useMessageStore((state) => state.loadMessageThroughHistory);
  const [navigatingMessageId, setNavigatingMessageId] = useState<string | null>(null);
  const [navigationError, setNavigationError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setNavigationError(null);
    setNavigatingMessageId(null);
    void loadBookmarks();
  }, [loadBookmarks, open]);

  const navigateToBookmark = async (messageId: string, channelId: string) => {
    setNavigatingMessageId(messageId);
    setNavigationError(null);
    try {
      const knownChannel = useChannelStore.getState().channels.find((channel) => channel.id === channelId);
      const channel = knownChannel || await api.getChannel(channelId);
      if (activeWorkspaceId !== channel.workspaceId) await setActiveWorkspace(channel.workspaceId);
      setActiveChannel(channelId);
      const found = await loadMessageThroughHistory(channelId, messageId, HISTORY_PAGE_LIMIT);
      if (!found) {
        setNavigationError(t('メッセージをまだ見つけられませんでした。チャンネルを上にスクロールして、さらに古いメッセージを読み込んでください。'));
        return;
      }
      await useForumStore.getState().revealMessage(channelId, messageId);
      close();
      window.setTimeout(() => {
        document.getElementById(`message-${messageId}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }, 100);
    } catch {
      setNavigationError(t('保存済みメッセージへ移動できませんでした。もう一度お試しください。'));
    } finally {
      setNavigatingMessageId(null);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={t('保存済みメッセージ')} description={t('保存済みメッセージから、元のチャンネルのメッセージへ移動できます。')} size="md">
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-discord-muted">{t('最大100件を新しい順に表示します。')}</p>
          <button type="button" onClick={() => void loadBookmarks()} disabled={loading} className="rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">{t('再読み込み')}</button>
        </div>
        {error && (
          <div role="alert" className="flex items-center justify-between gap-3 rounded bg-discord-red/10 p-3 text-sm text-discord-red">
            <span>{t('保存済みメッセージを読み込めませんでした')}</span>
            <button type="button" onClick={clearBookmarkError} className="underline">{t('閉じる')}</button>
          </div>
        )}
        {navigationError && (
          <div role="alert" className="rounded bg-yellow-500/10 p-3 text-sm text-yellow-200">
            <p>{navigationError}</p>
            <button type="button" onClick={close} className="mt-2 underline">{t('閉じてチャンネルを表示')}</button>
          </div>
        )}
        {loading && <p role="status" className="py-6 text-center text-sm text-discord-muted">{t('保存済みメッセージを読み込み中…')}</p>}
        {!loading && bookmarks.length === 0 && <p className="py-6 text-center text-sm text-discord-muted">{t('保存済みメッセージはありません。')}</p>}
        <ul className="space-y-2">
          {bookmarks.map((bookmark) => {
            const channel = channels.find((candidate) => candidate.id === bookmark.channelId);
            const message = messagesByChannel[bookmark.channelId]?.find((candidate) => candidate.id === bookmark.messageId);
            const navigating = navigatingMessageId === bookmark.messageId;
            return (
              <li key={bookmark.messageId} className="flex items-start gap-2 rounded bg-discord-bg/50 p-3">
                <button
                  type="button"
                  onClick={() => void navigateToBookmark(bookmark.messageId, bookmark.channelId)}
                  disabled={Boolean(navigatingMessageId)}
                  className="min-w-0 flex-1 rounded text-left disabled:opacity-60"
                  aria-label={t('{name}の保存済みメッセージへ移動', { name: channel?.name || t('保存先チャンネル') })}
                >
                  <span className="block text-xs text-discord-muted">#{channel?.name || t('保存先チャンネル')} · {formatDateTime(bookmark.createdAt)}</span>
                  <span className="mt-1 line-clamp-2 block break-words text-sm text-discord-text">
                    {navigating
                      ? t('履歴を読み込み中…')
                      : message?.type === 'delete'
                        ? t('削除されたメッセージ')
                        : message?.content
                          ? userFacingMessageText(message.content)
                          : t('本文を表示するには、チャンネルを開いて読み込んでください。')}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => void toggleBookmark(bookmark.messageId).catch(() => undefined)}
                  disabled={Boolean(savingByMessage[bookmark.messageId]) || Boolean(navigatingMessageId)}
                  className="rounded px-2 py-1 text-sm text-discord-red hover:bg-discord-red/10 disabled:opacity-50"
                  aria-label={t('保存済みから削除')}
                >
                  {t('削除')}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </Dialog>
  );
}
