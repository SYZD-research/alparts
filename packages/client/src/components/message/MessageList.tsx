import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useOutboxStore } from '../../stores/outbox.store';
import { useAuthStore } from '../../stores/auth.store';
import { MessageItem } from './MessageItem';
import type { Message } from '@alparts/shared';
import { useUserStateStore } from '../../stores/user-state.store';
import { latestReadableMessageId } from '../../stores/user-state-model';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { countLoadedThreadReplies, loadedThreadReplies } from '../../stores/thread-model';
import { ThreadPanel } from './ThreadPanel';

interface Props {
  channelId: string;
}

const EMPTY_MESSAGES: Message[] = [];

export function MessageList({ channelId }: Props) {
  const [threadRootId, setThreadRootId] = useState<string | null>(null);
  const messages = useMessageStore((state) => state.messagesByChannel[channelId] || EMPTY_MESSAGES);
  const isLoading = useMessageStore((state) => Boolean(state.loadingByChannel[channelId]));
  const isLoadingMore = useMessageStore((state) => Boolean(state.loadingMoreByChannel[channelId]));
  const hasMore = useMessageStore((state) => Boolean(state.hasMore[channelId]));
  const loadMoreMessages = useMessageStore((state) => state.loadMoreMessages);
  const outboxItems = useOutboxStore((state) => state.items);
  const retryOutboxItem = useOutboxStore((state) => state.retry);
  const user = useAuthStore((state) => state.user);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
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
  const threadCounts = useMemo(() => countLoadedThreadReplies(messages), [messages]);
  const threadRoot = useMemo(
    () => messages.find((message) => message.id === threadRootId) || null,
    [messages, threadRootId],
  );
  const threadReplies = useMemo(
    () => threadRootId ? loadedThreadReplies(messages, threadRootId) : [],
    [messages, threadRootId],
  );
  const channelOutboxItems = Object.values(outboxItems)
    .filter((item) => item.channelId === channelId)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id));
  const containerRef = useRef<HTMLDivElement>(null);
  const lastChannelId = useRef<string | null>(null);
  const initiallyScrolled = useRef(false);
  const shouldStickToBottom = useRef(true);

  useEffect(() => {
    setThreadRootId(null);
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
    if (!channelStateReady || !latestBaseMessageId || latestBaseMessageId === lastReadMessageId) return;
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
  }, [channelId, channelStateReady, lastReadMessageId, latestBaseMessageId, markRead]);

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

  if (isLoading && messages.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-discord-muted">読み込み中...</div>
      </div>
    );
  }

  // Group consecutive messages from the same author
  const groupedMessages: Array<{ message: Message; isFirst: boolean }> = [];
  messages.forEach((msg, i) => {
    const prev = messages[i - 1];
    const isFirst = !prev ||
      prev.authorId !== msg.authorId ||
      new Date(msg.createdAt).getTime() - new Date(prev.createdAt).getTime() > 5 * 60 * 1000;
    groupedMessages.push({ message: msg, isFirst });
  });

  return (
    <>
      <ThreadPanel
        channelId={channelId}
        root={threadRoot}
        replies={threadReplies}
        onClose={() => setThreadRootId(null)}
      />
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-4 py-2"
      >
      {isLoadingMore && (
        <div className="text-center py-2 text-discord-muted text-sm">
          さらに読み込み中...
        </div>
      )}

      {messages.length === 0 && channelOutboxItems.length === 0 && (
        <div className="flex items-center justify-center h-full">
          <div className="text-center text-discord-muted">
            <div className="text-4xl mb-2">#</div>
            <p className="font-bold text-lg text-discord-text">このチャンネルの始まりです</p>
            <p>最初のメッセージを送信しましょう！</p>
          </div>
        </div>
      )}

        {groupedMessages.map(({ message, isFirst }) => (
          <MessageItem
            key={message.id}
            message={message}
            isFirst={isFirst}
            replyCount={message.refMessageId ? 0 : threadCounts[message.id] || 0}
            onOpenThread={setThreadRootId}
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
              <span className="font-medium text-white">{user?.displayName || '自分'}</span>
              <span className="text-xs text-discord-muted">
                {item.status === 'sending' && '送信中…'}
                {item.status === 'queued' && '未送信・自動再送待ち'}
                {item.status === 'failed' && '送信失敗'}
              </span>
            </div>
            <p className="whitespace-pre-wrap break-words text-discord-text">{item.content}</p>
            {item.status !== 'sending' && (
              <button type="button" onClick={() => retryOutboxItem(item.id)} className="mt-1 text-xs text-discord-muted underline hover:text-discord-text">
                {item.error ? `${item.error} — 再試行` : '今すぐ再試行'}
              </button>
            )}
          </div>
        </div>
        ))}
      </div>
    </>
  );
}
