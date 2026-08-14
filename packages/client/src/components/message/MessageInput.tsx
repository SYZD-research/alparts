import { useState, useRef, useCallback } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { getSocket } from '../../services/socket';

interface Props {
  channelId: string;
}

export function MessageInput({ channelId }: Props) {
  const [content, setContent] = useState('');
  const [isSending, setIsSending] = useState(false);
  const { sendMessage } = useMessageStore();
  const typingTimeout = useRef<ReturnType<typeof setTimeout>>();
  const lastTypingSent = useRef<number>(0);

  const handleTyping = useCallback(() => {
    const socket = getSocket();
    if (!socket) return;

    const now = Date.now();
    if (now - lastTypingSent.current > 3000) {
      socket.emit('typing:start', { channelId });
      lastTypingSent.current = now;
    }

    if (typingTimeout.current) {
      clearTimeout(typingTimeout.current);
    }
    typingTimeout.current = setTimeout(() => {
      socket.emit('typing:stop', { channelId });
    }, 3000);
  }, [channelId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || isSending) return;

    setIsSending(true);
    try {
      await sendMessage(channelId, content.trim());
      setContent('');

      // Stop typing indicator
      const socket = getSocket();
      if (socket) {
        socket.emit('typing:stop', { channelId });
      }
    } catch (err) {
      console.error('Failed to send message:', err);
    } finally {
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="px-4 pb-6 pt-2">
      <form onSubmit={handleSubmit} className="relative">
        <textarea
          value={content}
          onChange={(e) => {
            setContent(e.target.value);
            handleTyping();
          }}
          onKeyDown={handleKeyDown}
          placeholder="メッセージを送信"
          className="w-full px-4 py-3 bg-discord-input rounded-lg text-discord-text placeholder-discord-muted outline-none resize-none focus:ring-1 focus:ring-discord-accent"
          rows={1}
          style={{ minHeight: '44px', maxHeight: '200px' }}
        />
      </form>
    </div>
  );
}
