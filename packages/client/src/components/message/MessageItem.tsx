import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { useMessageStore } from '../../stores/message.store';
import { useAuthStore } from '../../stores/auth.store';
import type { Message } from '@alparts/shared';

interface Props {
  message: Message;
  isFirst: boolean;
}

export function MessageItem({ message, isFirst }: Props) {
  const [showActions, setShowActions] = useState(false);
  const { deleteMessage, toggleReaction } = useMessageStore();
  const { user } = useAuthStore();

  const isOwn = message.authorId === user?.id;
  const isDeleted = message.type === 'delete';
  const isReaction = message.type === 'reaction';

  if (isReaction) return null;
  if (isDeleted) {
    return (
      <div className="text-discord-muted text-sm italic py-1 px-4">
        メッセージが削除されました
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
    toggleReaction(message.id, emoji);
  };

  const handleDelete = () => {
    if (confirm('このメッセージを削除しますか？')) {
      deleteMessage(message.id, message.channelId);
    }
  };

  return (
    <div
      className={`group relative flex gap-4 py-0.5 px-4 hover:bg-discord-hover/30 ${
        isFirst ? 'mt-4 pt-2' : ''
      }`}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
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

        <div className="text-discord-text leading-relaxed break-words prose prose-invert prose-sm max-w-none">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {message.content || ''}
          </ReactMarkdown>
        </div>

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
          {isOwn && (
            <button
              onClick={handleDelete}
              className="px-2 py-1 hover:bg-discord-red hover:text-white text-discord-muted text-sm"
              title="削除"
            >
              🗑
            </button>
          )}
        </div>
      )}
    </div>
  );
}
