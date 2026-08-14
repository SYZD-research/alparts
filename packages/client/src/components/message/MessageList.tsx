import { useEffect, useRef } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { MessageItem } from './MessageItem';
import type { Message } from '@alparts/shared';

interface Props {
  channelId: string;
}

export function MessageList({ channelId }: Props) {
  const { messagesByChannel, isLoading, hasMore, loadMoreMessages } = useMessageStore();
  const messages = messagesByChannel[channelId] || [];
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Scroll to bottom on new messages
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  const handleScroll = () => {
    const container = containerRef.current;
    if (!container) return;
    if (container.scrollTop === 0 && hasMore[channelId]) {
      loadMoreMessages(channelId);
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
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="flex-1 overflow-y-auto px-4 py-2"
    >
      {hasMore[channelId] && (
        <div className="text-center py-2 text-discord-muted text-sm">
          さらに読み込み中...
        </div>
      )}

      {messages.length === 0 && (
        <div className="flex items-center justify-center h-full">
          <div className="text-center text-discord-muted">
            <div className="text-4xl mb-2">#</div>
            <p className="font-bold text-lg text-discord-text">このチャンネルの始まりです</p>
            <p>最初のメッセージを送信しましょう！</p>
          </div>
        </div>
      )}

      {groupedMessages.map(({ message, isFirst }) => (
        <MessageItem key={message.id} message={message} isFirst={isFirst} />
      ))}

      <div ref={bottomRef} />
    </div>
  );
}
