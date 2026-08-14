import { useEffect, useRef } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { MessageList } from '../message/MessageList';
import { MessageInput } from '../message/MessageInput';

export function ChatArea() {
  const { activeChannelId } = useChannelStore();
  const { loadMessages, messagesByChannel } = useMessageStore();

  useEffect(() => {
    if (activeChannelId) {
      loadMessages(activeChannelId);
    }
  }, [activeChannelId]);

  if (!activeChannelId) return null;

  const channel = useChannelStore.getState().channels.find(c => c.id === activeChannelId);

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-discord-bg">
      {/* Channel header */}
      <div className="h-12 px-4 flex items-center border-b border-discord-sidebar shadow-sm">
        <span className="text-discord-muted mr-2">#</span>
        <h3 className="font-bold text-white">{channel?.name || 'チャンネル'}</h3>
        {channel?.topic && (
          <>
            <div className="w-px h-6 bg-discord-hover mx-3" />
            <span className="text-sm text-discord-muted truncate">{channel.topic}</span>
          </>
        )}
      </div>

      {/* Messages */}
      <MessageList channelId={activeChannelId} />

      {/* Input */}
      <MessageInput channelId={activeChannelId} />
    </div>
  );
}
