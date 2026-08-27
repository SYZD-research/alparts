import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { useMessageStore } from '../../stores/message.store';
import { useAuthStore } from '../../stores/auth.store';
import type { Message } from '@alparts/shared';
import { useUserStateStore } from '../../stores/user-state.store';
import { AttachmentItem } from './AttachmentItem';
import { safeMarkdownHref } from '../../services/url-policy';
import { useChannelStore } from '../../stores/channel.store';
import { buildMessagePermalink } from '../../stores/permalink-model';

interface Props {
  message: Message;
  isFirst: boolean;
  replyCount?: number;
  onOpenThread?: (messageId: string) => void;
}

export function MessageItem({ message, isFirst, replyCount = 0, onOpenThread }: Props) {
  const [showActions, setShowActions] = useState(false);
  const [bookmarkFailure, setBookmarkFailure] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [fallbackLink, setFallbackLink] = useState<string | null>(null);
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

  const handleCopyLink = async () => {
    if (!permalinkPath) {
      setCopyStatus('安全なメッセージリンクを作成できませんでした');
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
        {replyCount > 0 && onOpenThread && (
          <button
            type="button"
            onClick={() => onOpenThread(message.id)}
            className="ml-2 text-xs not-italic text-discord-accent underline"
            aria-label={`${replyCount}件の読み込み済み返信を開く`}
          >
            {replyCount}件の返信
          </button>
        )}
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

  const timestamp = new Date(message.createdAt).toLocaleTimeString('ja-JP', {
    hour: '2-digit',
    minute: '2-digit',
  });

  const date = new Date(message.createdAt).toLocaleDateString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });

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
    void toggleBookmark(message.id).catch((error: unknown) => {
      setBookmarkFailure(error instanceof Error ? error.message : 'ブックマークを更新できませんでした');
    });
  };

  return (
    <div
      id={`message-${message.id}`}
      className={`group relative flex gap-4 py-0.5 px-4 hover:bg-discord-hover/30 ${
        isFirst ? 'mt-4 pt-2' : ''
      }`}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
      onFocus={() => setShowActions(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setShowActions(false);
      }}
      tabIndex={0}
    >
      {isFirst ? (
        <div className="flex-shrink-0 w-10 h-10 rounded-full bg-discord-accent flex items-center justify-center text-white font-bold mt-0.5">
          {(message.author?.displayName || '?').slice(0, 1).toUpperCase()}
        </div>
      ) : (
        <div className="flex-shrink-0 w-10 text-xs text-discord-muted text-center opacity-0 group-hover:opacity-100 pt-1">
          {timestamp}
        </div>
      )}

      <div className="flex-1 min-w-0">
        {isFirst && (
          <div className="flex items-baseline gap-2 mb-0.5">
            <span className="font-medium text-white hover:underline cursor-pointer">
              {message.author?.displayName || '不明なユーザー'}
            </span>
            <span className="text-xs text-discord-muted">
              {date} {timestamp}
            </span>
          </div>
        )}

        {referencedMessage && (
          <div className="mb-1 border-l-2 border-discord-muted pl-2 text-xs text-discord-muted">
            <span className="font-medium">{referencedMessage.author.displayName}: </span>
            <span className="line-clamp-1">{referencedMessage.type === 'delete' ? '削除されたメッセージ' : referencedMessage.content}</span>
          </div>
        )}

        <div className="text-discord-text leading-relaxed break-words prose prose-invert prose-sm max-w-none">
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              img: ({ alt }) => (
                <span role="img" aria-label={alt || '外部画像'} className="text-discord-muted italic">
                  [外部画像は自動取得しません{alt ? `: ${alt}` : ''}]
                </span>
              ),
              a: ({ href, children }) => {
                const safeHref = safeMarkdownHref(href);
                return safeHref ? (
                  <a href={safeHref} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">
                    {children}
                  </a>
                ) : <span title="安全でないURL schemeを除外しました">{children}</span>;
              },
            }}
          >
            {message.content || ''}
          </ReactMarkdown>
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
        {replyCount > 0 && onOpenThread && (
          <button
            type="button"
            onClick={() => onOpenThread(message.id)}
            className="mt-1 text-xs font-medium text-discord-accent hover:underline"
            aria-label={`${replyCount}件の読み込み済み返信を開く`}
          >
            {replyCount}件の返信（読み込み済み）
          </button>
        )}
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
      {showActions && (
        <div className="absolute -top-4 right-4 flex bg-discord-sidebar rounded border border-discord-hover shadow">
          <button
            onClick={() => handleReaction('👍')}
            className="px-2 py-1 hover:bg-discord-hover text-discord-muted hover:text-discord-text text-sm"
            title="リアクション"
          >
            👍
          </button>
          <button
            onClick={() => setReplyTarget(message.channelId, message)}
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
            title="恒久リンクをコピー"
            aria-label="メッセージへの恒久リンクをコピー"
          >
            🔗
          </button>
          {isOwn && (
            <>
              <button
                onClick={() => setEditTarget(message.channelId, message)}
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
  );
}
