import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useOutboxStore } from '../../stores/outbox.store';
import { useAuthStore } from '../../stores/auth.store';
import { MessageItem } from './MessageItem';
import type { Message } from '@alparts/shared';
import { useUserStateStore } from '../../stores/user-state.store';
import { latestReadableMessageId } from '../../stores/user-state-model';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { focusMessageElement } from '../../services/message-navigation';
import { MessageContent } from './MessageContent';
import { useT } from '../../i18n';

interface Props {
  channelId: string;
  visible?: boolean;
}

const EMPTY_MESSAGES: Message[] = [];

export function MessageList({ channelId, visible: chatVisible = true }: Props) {
  const t = useT();
  const [jumpError, setJumpError] = useState<string | null>(null);
  const messages = useMessageStore((state) => state.messagesByChannel[channelId] || EMPTY_MESSAGES);
  const isLoading = useMessageStore((state) => Boolean(state.loadingByChannel[channelId]));
  const isLoadingMore = useMessageStore((state) => Boolean(state.loadingMoreByChannel[channelId]));
  const hasMore = useMessageStore((state) => Boolean(state.hasMore[channelId]));
  const loadMoreMessages = useMessageStore((state) => state.loadMoreMessages);
  const loadMessageThroughHistory = useMessageStore((state) => state.loadMessageThroughHistory);
  const outboxItems = useOutboxStore((state) => state.items);
  const retryOutboxItem = useOutboxStore((state) => state.retry);
  const user = useAuthStore((state) => state.user);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const workspaceMembers = useWorkspaceStore((state) => state.members);
  const lastReadMessageId = useUserStateStore((state) => activeWorkspaceId
    ? state.channelStatesByWorkspace[activeWorkspaceId]?.[channelId]?.lastReadMessageId || null
    : null);
  const channelStateReady = useUserStateStore((state) => Boolean(
    activeWorkspaceId && state.channelStatesByWorkspace[activeWorkspaceId]?.[channelId],
  ));
  const markRead = useUserStateStore((state) => state.markRead);
  // Use the logical projection so an append-only delete event removes its
  // target. Edit projections retain the base-message id and ordering.
  const latestBaseMessageId = useMemo(() => latestReadableMessageId(messages), [messages]);
  const channelOutboxItems = Object.values(outboxItems)
    .filter((item) => item.channelId === channelId)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id));
  const containerRef = useRef<HTMLDivElement>(null);
  const lastChannelId = useRef<string | null>(null);
  const initiallyScrolled = useRef(false);
  const shouldStickToBottom = useRef(true);

  useEffect(() => {
    setJumpError(null);
  }, [channelId]);

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    if (lastChannelId.current !== channelId) {
      lastChannelId.current = channelId;
      initiallyScrolled.current = false;
      shouldStickToBottom.current = true;
    }
    if (!initiallyScrolled.current && messages.length > 0) {
      container.scrollTop = container.scrollHeight;
      initiallyScrolled.current = true;
    } else if (shouldStickToBottom.current) {
      container.scrollTop = container.scrollHeight;
    }
  }, [channelId, channelOutboxItems.length, messages.length]);

  useEffect(() => {
    if (!chatVisible || !channelStateReady || !latestBaseMessageId || latestBaseMessageId === lastReadMessageId) return;
    const container = containerRef.current;
    const target = document.getElementById(`message-${latestBaseMessageId}`);
    if (!container || !target) return;

    const markWhenVisible = () => {
      const containerRect = container.getBoundingClientRect();
      const targetRect = target.getBoundingClientRect();
      const visible = targetRect.bottom > containerRect.top && targetRect.top < containerRect.bottom;
      if (visible && document.visibilityState === 'visible' && document.hasFocus()) {
        void markRead(channelId, latestBaseMessageId);
      }
    };
    const observer = typeof IntersectionObserver === 'undefined'
      ? null
      : new IntersectionObserver((entries) => {
        if (entries.some((entry) => entry.isIntersecting)) markWhenVisible();
      }, { root: container, threshold: 0.25 });
    observer?.observe(target);
    const frame = requestAnimationFrame(markWhenVisible);
    window.addEventListener('focus', markWhenVisible);
    document.addEventListener('visibilitychange', markWhenVisible);
    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
      window.removeEventListener('focus', markWhenVisible);
      document.removeEventListener('visibilitychange', markWhenVisible);
    };
  }, [channelId, channelStateReady, chatVisible, lastReadMessageId, latestBaseMessageId, markRead]);

  const handleScroll = () => {
    const container = containerRef.current;
    if (!container) return;
    shouldStickToBottom.current = container.scrollHeight - container.clientHeight - container.scrollTop < 80;
    if (container.scrollTop <= 1 && hasMore && !isLoadingMore) {
      const previousHeight = container.scrollHeight;
      shouldStickToBottom.current = false;
      void loadMoreMessages(channelId).finally(() => {
        requestAnimationFrame(() => {
          const current = containerRef.current;
          if (current) current.scrollTop += current.scrollHeight - previousHeight;
        });
      });
    }
  };

  const jumpToReferencedMessage = async (messageId: string) => {
    setJumpError(null);
    let found = Boolean(document.getElementById(`message-${messageId}`));
    if (!found) found = await loadMessageThroughHistory(channelId, messageId, 20);
    if (!found || !await focusMessageElement(messageId)) {
      setJumpError(t('返信先のメッセージを読み込めませんでした'));
    }
  };

  if (isLoading && messages.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-discord-muted">{t('読み込み中…')}</div>
      </div>
    );
  }

  // Group consecutive messages from the same author
  const groupedMessages: Array<{ message: Message; isFirst: boolean }> = [];
  messages.forEach((msg, i) => {
    const prev = messages[i - 1];
    const isFirst = !prev ||
      prev.authorId !== msg.authorId ||
      Boolean(msg.refMessageId) ||
      new Date(msg.createdAt).getTime() - new Date(prev.createdAt).getTime() > 5 * 60 * 1000;
    groupedMessages.push({ message: msg, isFirst });
  });

  return (
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-4 py-2"
      >
      {isLoadingMore && (
        <div className="text-center py-2 text-discord-muted text-sm">
          {t('さらに読み込み中...')}
        </div>
      )}

      {jumpError && (
        <div role="alert" className="sticky top-1 z-10 mx-4 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
          <span>{jumpError}</span>
          <button type="button" onClick={() => setJumpError(null)} className="underline">{t('閉じる')}</button>
        </div>
      )}

      {messages.length === 0 && channelOutboxItems.length === 0 && (
        <div className="flex items-center justify-center h-full">
          <div className="text-center text-discord-muted">
            <div className="text-4xl mb-2">#</div>
            <p className="font-bold text-lg text-discord-text">{t('このチャンネルの始まりです')}</p>
            <p>{t('最初のメッセージを送信しましょう！')}</p>
          </div>
        </div>
      )}

        {groupedMessages.map(({ message, isFirst }) => (
          <MessageItem
            key={message.id}
            message={message}
            isFirst={isFirst}
            onJumpToMessage={(messageId) => { void jumpToReferencedMessage(messageId); }}
          />
        ))}

        {channelOutboxItems.map((item) => (
        <div
          key={item.id}
          data-outbox-status={item.status}
          className="mt-4 flex gap-4 rounded px-4 py-2 opacity-75 hover:bg-discord-hover/30"
        >
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-discord-accent font-bold text-white">
            {(user?.displayName || '?').slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2">
              <span className="font-medium text-white">{user?.displayName || t('自分')}</span>
              <span className="text-xs text-discord-muted">
                {item.status === 'sending' && t('送信中…')}
                {item.status === 'queued' && t('未送信・自動送信待ち')}
                {item.status === 'failed' && t('送信失敗')}
              </span>
            </div>
            <div className="break-words text-discord-text">
              <MessageContent
                content={item.content}
                members={workspaceMembers}
                currentUserId={user?.id || null}
              />
            </div>
            {item.status !== 'sending' && (
              <button type="button" onClick={() => retryOutboxItem(item.id)} className="mt-1 text-xs text-discord-muted underline hover:text-discord-text">
                {item.status === 'failed' ? t('送信できませんでした — 再試行') : t('今すぐ再試行')}
              </button>
            )}
          </div>
        </div>
        ))}
      </div>
  );
}
