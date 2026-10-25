import { useMemo, useState } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { quotedMessage } from '../../stores/message-projector';
import { useAuthStore } from '../../stores/auth.store';
import type { Message } from '@alparts/shared';
import { useUserStateStore } from '../../stores/user-state.store';
import { AttachmentItem } from './AttachmentItem';
import { useChannelStore } from '../../stores/channel.store';
import { buildMessagePermalink } from '../../stores/permalink-model';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { isPictureHidden } from '../../stores/profile-visibility';
import { messageMentionsCurrentUser } from '../../services/mention-model';
import { MessageContent } from './MessageContent';
import { userFacingMessageText } from '../../services/message-display';
import { useHorizontalSwipe } from '../../hooks/useHorizontalSwipe';
import { canSwipeMessage, messageSwipeAction } from './message-swipe-model';
import { formatDateParts } from '../../stores/date-format';
import { useUiStore } from '../../stores/ui.store';
import { UserAvatar } from '../user/UserAvatar';
import { Icon } from '../ui/Icon';
import { useT } from '../../i18n';

const MESSAGE_TOOL = 'flex h-8 w-8 items-center justify-center rounded-lg transition-colors disabled:opacity-40';
const QUIET_TOOL = `${MESSAGE_TOOL} text-muted hover:bg-hover hover:text-ink-strong`;

interface Props {
  message: Message;
  isFirst: boolean;
  onJumpToMessage?: (messageId: string) => void;
  /** Forum replies cannot be pinned; only whole posts can. */
  canPin?: boolean;
}

export function MessageItem({ message, isFirst, onJumpToMessage, canPin = true }: Props) {
  const t = useT();
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
  // Null when the message under the quoted id is not the one this message
  // was signed quoting: neither it nor a link to it is shown.
  const referencedMessage = useMessageStore((state) => (
    message.refMessageId
      ? quotedMessage(message, state.messagesByChannel[message.channelId] ?? [])
      : undefined
  ));
  const attachmentKeyMessage = useMessageStore((state) => (
    state.eventsByChannel[message.channelId]?.find((event) => event.id === message.id && event.type === 'message')
  ));
  const user = useAuthStore((state) => state.user);
  const workspaceMembers = useWorkspaceStore((state) => state.members);
  const warnedUsers = useWorkspaceStore((state) => state.warnedUsers);
  // Pictures of profiles an administrator warned about stay hidden, also for former members.
  const authorFlagged = isPictureHidden(message.authorId, workspaceMembers, warnedUsers);
  const referencedAuthorFlagged = Boolean(referencedMessage && isPictureHidden(referencedMessage.authorId, workspaceMembers, warnedUsers));
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
      setCopyStatus(t('メッセージへのリンクを作成できませんでした'));
      return;
    }
    const link = new URL(permalinkPath, window.location.origin).toString();
    setFallbackLink(null);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(link);
      setCopyStatus(t('メッセージリンクをコピーしました'));
    } catch {
      setFallbackLink(link);
      setCopyStatus(t('自動コピーできませんでした。下のリンクを選択してコピーしてください'));
    }
  };

  if (isDeleted) {
    return (
      <div id={`message-${message.id}`} tabIndex={-1} className="px-4 py-1 text-sm italic text-muted">
        <span>{t('メッセージが削除されました')}</span>
        <button
          type="button"
          onClick={() => { void handleCopyLink(); }}
          disabled={!permalinkPath}
          className="ml-2 text-xs not-italic underline disabled:opacity-50"
          aria-label={t('削除されたメッセージへのリンクをコピー')}
        >
          {t('リンク')}
        </button>
        {copyStatus && <span role="status" className="ml-2 text-xs not-italic">{copyStatus}</span>}
        {fallbackLink && (
          <label className="mt-1 block text-xs not-italic">
            {t('コピー用リンク')}
            <input
              readOnly
              value={fallbackLink}
              onFocus={(event) => event.currentTarget.select()}
              className="mt-1 block w-full rounded-lg bg-field px-2 py-1 text-ink"
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
    if (confirm(t('このメッセージを削除しますか？'))) {
      void deleteMessage(message.id, message.channelId).catch(() => undefined);
    }
  };

  const handleBookmark = () => {
    setBookmarkFailure(null);
    void toggleBookmark(message.id).catch(() => {
      setBookmarkFailure(t('保存状態を更新できませんでした。もう一度お試しください'));
    });
  };

  return (
    <div
      id={`message-${message.id}`}
      data-self-mention={mentionsCurrentUser ? 'true' : undefined}
      className={`message-swipe group relative rounded-lg ${
        mentionsCurrentUser ? '' : 'hover:bg-hover/45'
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
            swipeAction ? 'text-accent' : 'text-muted'
          }`}
          role="status"
        >
          <Icon name={swipeAction === 'edit' ? 'pencil' : 'reply'} size={20} />
          <span>{swipeAction === 'edit' ? t('編集') : t('返信')}</span>
        </div>
      )}
      <div
        className={`message-swipe-content relative flex w-full gap-4 px-4 py-0.5 ${isFirst ? 'pt-2' : ''} ${swipe.isDragging ? 'bg-canvas' : ''}`}
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
          <div className={`shrink-0 w-10 text-xs text-muted text-center opacity-0 group-hover:opacity-100 ${message.refMessageId ? 'pt-7' : 'pt-1'}`}>
            {timestamp}
          </div>
        )}

        <div className="flex-1 min-w-0">
          {message.refMessageId && (
            <button
              type="button"
              onClick={() => onJumpToMessage?.(message.refMessageId!)}
              disabled={!onJumpToMessage || referencedMessage === null}
              className="mb-1 flex max-w-full items-center gap-1.5 rounded-md bg-panel/70 py-0.5 pl-1.5 pr-2 text-left text-xs text-muted transition-colors hover:bg-hover hover:text-ink disabled:cursor-default disabled:hover:bg-panel/70"
              aria-label={t('返信先のメッセージへ移動')}
            >
              <Icon name="reply" size={13} />
              <UserAvatar
                displayName={referencedMessage?.author?.displayName || '?'}
                avatarUrl={referencedMessage?.author?.avatarUrl}
                hidden={referencedAuthorFlagged}
                size="xs"
              />
              {referencedMessage ? (
                <>
                  <span className="shrink-0 font-medium text-ink-soft">{referencedMessage.author?.displayName || t('不明なユーザー')}</span>
                  <span className="truncate">
                    {referencedMessage.type === 'delete'
                      ? t('削除されたメッセージ')
                      : userFacingMessageText(referencedMessage.content || '') || (referencedMessage.attachments?.length ? t('添付ファイル') : t('本文なし'))}
                  </span>
                </>
              ) : referencedMessage === null ? (
                <span className="truncate">{t('元のメッセージを表示できません')}</span>
              ) : (
                <span className="truncate hover:underline">{t('元のメッセージを表示')}</span>
              )}
            </button>
          )}
          {isFirst && (
            <div className="flex items-baseline gap-2 mb-0.5">
              <button
                type="button"
                onClick={() => { if (activeWorkspaceId) openMemberProfile(activeWorkspaceId, message.authorId); }}
                className="font-semibold text-ink-strong hover:underline"
              >
                {message.author?.displayName || t('不明なユーザー')}
              </button>
              <span className="text-xs text-muted">
                {date} {timestamp}
              </span>
            </div>
          )}

          <div className="message-markdown wrap-break-word text-ink">
            <MessageContent
              content={message.content || ''}
              members={workspaceMembers}
              currentUserId={user?.id || null}
              authenticatedBroadcastMention={message.broadcastMention === true}
            />
            {message.type === 'edit' && <span className="ml-1 text-xs text-muted">{t('（編集済み）')}</span>}
            {message.isPinned && <span className="ml-2 text-xs text-warning">{t('📌 ピン留め')}</span>}
            {bookmarked && <span className="ml-2 text-xs text-accent">{t('🔖 保存済み')}</span>}
          </div>
          {message.attachments?.map((attachment) => (
            <AttachmentItem
              key={attachment.id}
              attachment={attachment}
              message={attachmentKeyMessage || message}
            />
          ))}
          {bookmarkFailure && <p role="alert" className="mt-1 text-xs text-danger">{bookmarkFailure}</p>}
          {copyStatus && <p role="status" className="mt-1 text-xs text-muted">{copyStatus}</p>}
          {fallbackLink && (
            <label className="mt-1 block text-xs text-muted">
              {t('コピー用リンク')}
              <input
                readOnly
                value={fallbackLink}
                onFocus={(event) => event.currentTarget.select()}
                className="mt-1 block w-full rounded-lg bg-field px-2 py-1 text-ink"
              />
            </label>
          )}

          {/* Reactions */}
          {message.reactions && message.reactions.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {message.reactions.map((reaction) => (
                <button
                  key={reaction.emoji}
                  type="button"
                  onClick={() => handleReaction(reaction.emoji)}
                  className={`flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-sm transition-colors ${
                    reaction.userIds?.includes(user?.id || '')
                      ? 'border-accent/45 bg-accent/10 text-accent'
                      : 'border-line bg-panel/60 text-ink-soft hover:border-line-strong hover:bg-hover'
                  }`}
                >
                  <span className="leading-none">{reaction.emoji}</span>
                  <span className="text-xs font-medium">{reaction.count}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Action buttons */}
        {showActions && !swipe.isDragging && (
          <div className="absolute -top-4 right-4 flex items-center gap-0.5 rounded-xl border border-line bg-raised p-1 shadow-lg shadow-black/30">
            <button
              type="button"
              onClick={() => handleReaction('👍')}
              className={`${QUIET_TOOL} text-[15px]`}
              title={t('リアクション')}
            >
              👍
            </button>
            <button
              type="button"
              onClick={() => selectMessageAction('reply')}
              className={QUIET_TOOL}
              title={t('返信')}
              aria-label={t('返信')}
            >
              <Icon name="reply" />
            </button>
            {canPin && (
              <button
                type="button"
                onClick={() => void pinMessage(message.id, message.channelId).catch(() => undefined)}
                className={`${MESSAGE_TOOL} hover:bg-hover ${message.isPinned ? 'text-warning' : 'text-muted hover:text-ink-strong'}`}
                title={message.isPinned ? t('ピンを外す') : t('ピン留め')}
                aria-label={message.isPinned ? t('ピンを外す') : t('ピン留め')}
              >
                <Icon name="pin" />
              </button>
            )}
            <button
              type="button"
              onClick={handleBookmark}
              disabled={bookmarkSaving}
              aria-pressed={bookmarked}
              aria-label={bookmarked ? t('保存済みメッセージから削除') : t('メッセージを保存')}
              className={`${MESSAGE_TOOL} hover:bg-hover ${bookmarked ? 'text-accent' : 'text-muted hover:text-ink-strong'}`}
              title={bookmarked ? t('保存済みから削除') : t('保存')}
            >
              <Icon name="bookmark" filled={bookmarked} />
            </button>
            <button
              type="button"
              onClick={() => { void handleCopyLink(); }}
              disabled={!permalinkPath}
              className={QUIET_TOOL}
              title={t('リンクをコピー')}
              aria-label={t('メッセージへのリンクをコピー')}
            >
              <Icon name="link" />
            </button>
            {isOwn && (
              <>
                <button
                  type="button"
                  onClick={() => selectMessageAction('edit')}
                  className={QUIET_TOOL}
                  title={t('編集')}
                  aria-label={t('編集')}
                >
                  <Icon name="pencil" />
                </button>
                <button
                  type="button"
                  onClick={handleDelete}
                  className={`${MESSAGE_TOOL} text-muted hover:bg-danger/15 hover:text-danger`}
                  title={t('削除')}
                  aria-label={t('削除')}
                >
                  <Icon name="trash" />
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
