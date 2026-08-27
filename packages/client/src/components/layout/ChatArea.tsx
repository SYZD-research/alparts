import { useEffect } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { usePresenceStore } from '../../stores/presence.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { MessageList } from '../message/MessageList';
import { MessageInput } from '../message/MessageInput';
import { getSocket } from '../../services/socket';
import { useDmStore } from '../../stores/dm.store';
import { useAuthStore } from '../../stores/auth.store';
import { directMessageTitle } from '../../stores/dm-model';
import { useUiStore } from '../../stores/ui.store';
import { VoiceCallPanel } from '../voice/VoiceCallPanel';

export function ChatArea() {
  const activeChannelId = useChannelStore((state) => state.activeChannelId);
  const channel = useChannelStore((state) => state.channels.find((candidate) => candidate.id === state.activeChannelId));
  const loadMessages = useMessageStore((state) => state.loadMessages);
  const securityError = useMessageStore((state) => activeChannelId ? state.securityErrors[activeChannelId] : null);
  const operationError = useMessageStore((state) => activeChannelId ? state.operationErrors[activeChannelId] : null);
  const clearOperationError = useMessageStore((state) => state.clearOperationError);
  const typingUsers = usePresenceStore((state) => activeChannelId ? state.typingUsers[activeChannelId] : undefined);
  const members = useWorkspaceStore((state) => state.members);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const currentUserId = useAuthStore((state) => state.user?.id);
  const dmConversation = useDmStore((state) => activeWorkspaceId && activeChannelId
    ? state.conversationsByWorkspace[activeWorkspaceId]?.find((conversation) => conversation.channelId === activeChannelId)
    : undefined);
  const openSavedMessages = useUiStore((state) => state.openSavedMessages);

  useEffect(() => {
    if (activeChannelId) {
      const socket = getSocket();
      socket?.emit('channel:join', activeChannelId, (result: { ok: boolean }) => {
        if (result.ok) void loadMessages(activeChannelId);
      });
      return () => {
        socket?.emit('channel:leave', activeChannelId);
      };
    }
  }, [activeChannelId, loadMessages]);

  if (!activeChannelId) return null;

  const typingNames = Object.keys(typingUsers || {}).map((userId) => (
    members.find((member) => member.userId === userId)?.user.displayName || 'ユーザー'
  ));

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-discord-bg">
      {/* Channel header */}
      <div className="h-12 px-4 flex items-center border-b border-discord-sidebar shadow-sm">
        <span className="text-discord-muted mr-2">{dmConversation ? '@' : '#'}</span>
        <h3 className="font-bold text-white">
          {dmConversation && currentUserId ? directMessageTitle(dmConversation, currentUserId) : channel?.name || 'チャンネル'}
        </h3>
        {channel?.topic && (
          <>
            <div className="w-px h-6 bg-discord-hover mx-3" />
            <span className="text-sm text-discord-muted truncate">{channel.topic}</span>
          </>
        )}
        <button type="button" onClick={openSavedMessages} className="ml-auto shrink-0 rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-white" aria-label="保存済みメッセージを開く">
          🔖 保存済み
        </button>
      </div>

      <VoiceCallPanel channelId={activeChannelId} />

      {securityError ? (
        <div role="alert" className="flex-1 flex items-center justify-center px-8 text-center text-discord-red">
          安全な暗号鍵を準備できないため、このチャンネルは停止しました。{securityError}
        </div>
      ) : (
        <>
          <MessageList channelId={activeChannelId} />
          {operationError && (
            <div role="alert" className="mx-4 mb-2 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
              <span>{operationError}</span>
              <button type="button" onClick={() => clearOperationError(activeChannelId)} className="underline">
                閉じる
              </button>
            </div>
          )}
          <div aria-live="polite" className="min-h-5 px-5 text-xs text-discord-muted">
            {typingNames.length > 0 ? `${typingNames.slice(0, 3).join('、')} が入力中…` : ''}
          </div>
          <MessageInput channelId={activeChannelId} />
        </>
      )}
    </div>
  );
}
