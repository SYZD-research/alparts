import { useMemo, useState } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useAuthStore } from '../../stores/auth.store';
import type { Message } from '@alparts/shared';
import { useUserStateStore } from '../../stores/user-state.store';
import { AttachmentItem } from './AttachmentItem';
import { useChannelStore } from '../../stores/channel.store';
import { buildMessagePermalink } from '../../stores/permalink-model';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { messageMentionsCurrentUser } from '../../services/mention-model';
import { MessageContent } from './MessageContent';
import { userFacingMessageText } from '../../services/message-display';
import { useHorizontalSwipe } from '../../hooks/useHorizontalSwipe';
import { canSwipeMessage, messageSwipeAction } from './message-swipe-model';
import { formatDateParts } from '../../stores/date-format';
import { useUiStore } from '../../stores/ui.store';
import { UserAvatar } from '../user/UserAvatar';

interface Props {
  message: Message;
  isFirst: boolean;
  onJumpToMessage?: (messageId: string) => void;
}

export function MessageItem({ message, isFirst, onJumpToMessage }: Props) {
  const [showActions, setShowActions] = useState(false);
  const [bookmarkFailure, setBookmarkFailure] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [fallbackLink, setFallbackLink] = useState<string | null>(null);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const openMemberProfile = useUiStore((state) => state.openMemberProfile);
  const deleteMessage = useMessageStore((state) => state.deleteMessage);
  const toggleReaction = useMessageStore((state) => state.toggleReaction);
  const pinMessage = useMessageStore((state) => state.pinMessage);
  const setReplyTarget = useMessageStore((state) => state.setReplyTarget);
  const setEditTarget = useMessageStore((state) => state.setEditTarget);
  const referencedMessage = useMessageStore((state) => (
    message.refMessageId
      ? state.messagesByChannel[message.channelId]?.find((candidate) => candidate.id === message.refMessageId)
      : undefined
  ));
  const attachmentKeyMessage = useMessageStore((state) => (
    state.eventsByChannel[message.channelId]?.find((event) => event.id === message.id && event.type === 'message')
  ));
  const user = useAuthStore((state) => state.user);
  const workspaceMembers = useWorkspaceStore((state) => state.members);
  // Pictures of profiles an administrator warned about stay hidden in lists.
  const authorFlagged = Boolean(workspaceMembers.find((member) => member.userId === message.authorId)?.profileFlagged);
  const referencedAuthorFlagged = Boolean(
    referencedMessage && workspaceMembers.find((member) => member.userId === referencedMessage.authorId)?.profileFlagged,
  );
  const mentionMembers = useMemo(() => workspaceMembers.map((member) => ({
    userId: member.userId,
    displayName: member.user.displayName,
  })), [workspaceMembers]);
  const mentionsCurrentUser = useMemo(() => messageMentionsCurrentUser(
    message.content || '',
    mentionMembers,
    user?.id || null,
    message.broadcastMention === true,
  ), [mentionMembers, message.broadcastMention, message.content, user?.id]);
  const bookmarked = useUserStateStore((state) => Boolean(state.bookmarkedMessageIds[message.id]));
  const bookmarkSaving = useUserStateStore((state) => Boolean(state.bookmarkSavingByMessage[message.id]));
  const toggleBookmark = useUserStateStore((state) => state.toggleBookmark);
  const workspaceId = useChannelStore((state) => (
    state.channels.find((channel) => channel.id === message.channelId)?.workspaceId || null
  ));
  const permalinkPath = workspaceId
    ? buildMessagePermalink({ workspaceId, channelId: message.channelId, messageId: message.id })
    : null;

  const isOwn = message.authorId === user?.id;
  const isDeleted = message.type === 'delete';
  const isReaction = message.type === 'reaction';

  const selectMessageAction = (action: 'reply' | 'edit') => {
    if (action === 'edit') setEditTarget(message.channelId, message);
    else setReplyTarget(message.channelId, message);
    // Focus during the touch release so mobile browsers can show the keyboard.
    document.getElementById(`message-input-${message.channelId}`)?.focus({ preventScroll: true });
  };
  const swipe = useHorizontalSwipe({
    enabled: Boolean(user) && canSwipeMessage(message),
    direction: 'left',
    onSwipe: (distanceX) => {
      const action = messageSwipeAction(distanceX, isOwn);
      if (action) selectMessageAction(action);
    },
  });
  const swipeAction = messageSwipeAction(swipe.offsetX, isOwn);

  const handleCopyLink = async () => {
    if (!permalinkPath) {
      setCopyStatus('メッセージへのリンクを作成できませんでした');
      return;
    }
    const link = new URL(permalinkPath, window.location.origin).toString();
    setFallbackLink(null);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(link);
      setCopyStatus('メッセージリンクをコピーしました');
    } catch {
      setFallbackLink(link);
      setCopyStatus('自動コピーできませんでした。下のリンクを選択してコピーしてください');
    }
  };

  if (isReaction) return null;
  if (isDeleted) {
    return (
      <div id={`message-${message.id}`} tabIndex={-1} className="px-4 py-1 text-sm italic text-discord-muted">
        <span>メッセージが削除されました</span>
        <button
          type="button"
          onClick={() => { void handleCopyLink(); }}
          disabled={!permalinkPath}
          className="ml-2 text-xs not-italic underline disabled:opacity-50"
          aria-label="削除されたメッセージへのリンクをコピー"
        >
          リンク
        </button>
        {copyStatus && <span role="status" className="ml-2 text-xs not-italic">{copyStatus}</span>}
        {fallbackLink && (
          <label className="mt-1 block text-xs not-italic">
            コピー用リンク
            <input
              readOnly
              value={fallbackLink}
              onFocus={(event) => event.currentTarget.select()}
              className="mt-1 block w-full rounded bg-discord-input px-2 py-1 text-discord-text"
            />
          </label>
        )}
      </div>
    );
  }

  const timestamp = formatDateParts(message.createdAt, { hour: '2-digit', minute: '2-digit' }, 'time');
  const date = formatDateParts(message.createdAt, { year: 'numeric', month: '2-digit', day: '2-digit' }, 'date');

  const handleReaction = (emoji: string) => {
    if (!user) return;
    void toggleReaction(message.id, emoji, message.channelId, user.id).catch(() => undefined);
  };

  const handleDelete = () => {
    if (confirm('このメッセージを削除しますか？')) {
      void deleteMessage(message.id, message.channelId).catch(() => undefined);
    }
  };

  const handleBookmark = () => {
    setBookmarkFailure(null);
    void toggleBookmark(message.id).catch(() => {
      setBookmarkFailure('保存状態を更新できませんでした。もう一度お試しください');
    });
  };

  return (
    <div
      id={`message-${message.id}`}
      data-self-mention={mentionsCurrentUser ? 'true' : undefined}
      className={`message-swipe group relative ${
        mentionsCurrentUser ? '' : 'hover:bg-discord-hover/30'
      } ${
        isFirst ? 'mt-4' : ''
      }`}
      {...swipe.handlers}
      style={{ touchAction: 'pan-y pinch-zoom', overflow: swipe.isDragging ? 'clip' : undefined }}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
      onFocus={() => setShowActions(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setShowActions(false);
      }}
      tabIndex={0}
    >
      {swipe.isDragging && swipe.offsetX < 0 && (
        <div
          className={`message-swipe-action pointer-events-none absolute inset-y-0 right-2 flex w-12 items-center justify-center gap-1 text-xs ${
            swipeAction ? 'text-discord-accent' : 'text-discord-muted'
          }`}
          role="status"
        >
          <span aria-hidden="true" className="text-xl leading-none">{swipeAction === 'edit' ? '✎' : '↩'}</span>
          <span>{swipeAction === 'edit' ? '編集' : '返信'}</span>
        </div>
      )}
      <div
        className={`message-swipe-content relative flex w-full gap-4 px-4 py-0.5 ${isFirst ? 'pt-2' : ''} ${swipe.isDragging ? 'bg-discord-bg' : ''}`}
        style={{ transform: swipe.isDragging ? `translateX(${Math.max(-184, swipe.offsetX)}px)` : undefined }}
      >
        {isFirst ? (
          <UserAvatar
            displayName={message.author?.displayName || '?'}
            avatarUrl={message.author?.avatarUrl}
            hidden={authorFlagged}
            className={message.refMessageId ? 'mt-6' : 'mt-0.5'}
          />
        ) : (
          <div className={`flex-shrink-0 w-10 text-xs text-discord-muted text-center opacity-0 group-hover:opacity-100 ${message.refMessageId ? 'pt-7' : 'pt-1'}`}>
            {timestamp}
          </div>
        )}

        <div className="flex-1 min-w-0">
          {message.refMessageId && (
            <button
              type="button"
              onClick={() => onJumpToMessage?.(message.refMessageId!)}
              disabled={!onJumpToMessage}
              className="relative mb-1 flex max-w-full items-center gap-1.5 text-left text-xs text-discord-muted hover:text-discord-text disabled:cursor-default"
              aria-label="返信先のメッセージへ移動"
            >
              <span aria-hidden="true" className="absolute -left-9 top-1/2 h-4 w-9 -translate-y-px rounded-tl-md border-l-2 border-t-2 border-discord-hover" />
              <UserAvatar
                displayName={referencedMessage?.author?.displayName || '?'}
                avatarUrl={referencedMessage?.author?.avatarUrl}
                hidden={referencedAuthorFlagged}
                size="xs"
              />
              {referencedMessage ? (
                <>
                  <span className="shrink-0 font-semibold text-discord-text">{referencedMessage.author?.displayName || '不明なユーザー'}</span>
                  <span className="truncate">
                    {referencedMessage.type === 'delete'
                      ? '削除されたメッセージ'
                      : userFacingMessageText(referencedMessage.content || '') || (referencedMessage.attachments?.length ? '添付ファイル' : '本文なし')}
                  </span>
                </>
              ) : (
                <span className="truncate hover:underline">元のメッセージを表示</span>
              )}
            </button>
          )}
          {isFirst && (
            <div className="flex items-baseline gap-2 mb-0.5">
              <button
                type="button"
                onClick={() => { if (activeWorkspaceId) openMemberProfile(activeWorkspaceId, message.authorId); }}
                className="font-medium text-white hover:underline"
              >
                {message.author?.displayName || '不明なユーザー'}
              </button>
              <span className="text-xs text-discord-muted">
                {date} {timestamp}
              </span>
            </div>
          )}

          <div className="text-discord-text leading-relaxed break-words prose prose-invert prose-sm max-w-none">
            <MessageContent
              content={message.content || ''}
              members={workspaceMembers}
              currentUserId={user?.id || null}
              authenticatedBroadcastMention={message.broadcastMention === true}
            />
            {message.type === 'edit' && <span className="ml-1 text-xs text-discord-muted">（編集済み）</span>}
            {message.isPinned && <span className="ml-2 text-xs text-discord-yellow">📌 ピン留め</span>}
            {bookmarked && <span className="ml-2 text-xs text-discord-accent">🔖 保存済み</span>}
          </div>
          {message.attachments?.map((attachment) => (
            <AttachmentItem
              key={attachment.id}
              attachment={attachment}
              message={attachmentKeyMessage || message}
            />
          ))}
          {bookmarkFailure && <p role="alert" className="mt-1 text-xs text-discord-red">{bookmarkFailure}</p>}
          {copyStatus && <p role="status" className="mt-1 text-xs text-discord-muted">{copyStatus}</p>}
          {fallbackLink && (
            <label className="mt-1 block text-xs text-discord-muted">
              コピー用リンク
              <input
                readOnly
                value={fallbackLink}
                onFocus={(event) => event.currentTarget.select()}
                className="mt-1 block w-full rounded bg-discord-input px-2 py-1 text-discord-text"
              />
            </label>
          )}

          {/* Reactions */}
          {message.reactions && message.reactions.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {message.reactions.map((reaction) => (
                <button
                  key={reaction.emoji}
                  onClick={() => handleReaction(reaction.emoji)}
                  className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-sm border ${
                    reaction.userIds?.includes(user?.id || '')
                      ? 'bg-discord-accent/20 border-discord-accent text-discord-accent'
                      : 'bg-discord-sidebar border-discord-hover text-discord-muted hover:border-discord-text'
                  }`}
                >
                  <span>{reaction.emoji}</span>
                  <span className="text-xs">{reaction.count}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Action buttons */}
        {showActions && !swipe.isDragging && (
          <div className="absolute -top-4 right-4 flex bg-discord-sidebar rounded border border-discord-hover shadow">
            <button
              onClick={() => handleReaction('👍')}
              className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm"
              title="リアクション"
            >
              👍
            </button>
            <button
              onClick={() => selectMessageAction('reply')}
              className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm"
              title="返信"
            >
              ↩
            </button>
            <button
              onClick={() => void pinMessage(message.id, message.channelId).catch(() => undefined)}
              className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm"
              title={message.isPinned ? 'ピンを外す' : 'ピン留め'}
            >
              📌
            </button>
            <button
              type="button"
              onClick={handleBookmark}
              disabled={bookmarkSaving}
              aria-pressed={bookmarked}
              aria-label={bookmarked ? '保存済みメッセージから削除' : 'メッセージを保存'}
              className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm disabled:opacity-50"
              title={bookmarked ? '保存済みから削除' : '保存'}
            >
              {bookmarked ? '🔖' : '♡'}
            </button>
            <button
              type="button"
              onClick={() => { void handleCopyLink(); }}
              disabled={!permalinkPath}
              className="px-2 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-discord-text disabled:opacity-40"
              title="リンクをコピー"
              aria-label="メッセージへのリンクをコピー"
            >
              🔗
            </button>
            {isOwn && (
              <>
                <button
                  onClick={() => selectMessageAction('edit')}
                  className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm"
                  title="編集"
                >
                  ✎
                </button>
                <button
                  onClick={handleDelete}
                  className="px-2 py-1 hover:bg-discord-red hover:text-white text-discord-muted text-sm"
                  title="削除"
                >
                  🗑
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
