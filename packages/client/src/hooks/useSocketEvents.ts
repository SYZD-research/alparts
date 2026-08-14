import { useEffect } from 'react';
import { getSocket } from '../services/socket';
import { useMessageStore } from '../stores/message.store';
import { usePresenceStore } from '../stores/presence.store';
import type { Message, UserStatusType } from '@alparts/shared';

export function useSocketEvents() {
  const { addMessage } = useMessageStore();
  const { setStatus, setTyping } = usePresenceStore();

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    // Message events
    const onMessageNew = (data: { message: Message }) => {
      addMessage(data.message.channelId, data.message);
    };

    const onMessageEdited = (data: { message: Message }) => {
      // TODO: Update message in store
    };

    const onMessageDeleted = (data: { messageId: string; channelId: string }) => {
      useMessageStore.getState().deleteMessage(data.messageId, data.channelId);
    };

    // Presence events
    const onPresenceChanged = (data: { userId: string; status: UserStatusType }) => {
      setStatus(data.userId, data.status);
    };

    // Typing events
    const onTypingUpdate = (data: { channelId: string; userId: string; isTyping: boolean }) => {
      setTyping(data.channelId, data.userId, data.isTyping);
    };

    socket.on('message:new', onMessageNew);
    socket.on('message:edited', onMessageEdited);
    socket.on('message:deleted', onMessageDeleted);
    socket.on('presence:changed', onPresenceChanged);
    socket.on('typing:update', onTypingUpdate);

    return () => {
      socket.off('message:new', onMessageNew);
      socket.off('message:edited', onMessageEdited);
      socket.off('message:deleted', onMessageDeleted);
      socket.off('presence:changed', onPresenceChanged);
      socket.off('typing:update', onTypingUpdate);
    };
  }, [addMessage, setStatus, setTyping]);
}
