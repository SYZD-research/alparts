import { Server as SocketServer } from 'socket.io';
import { AuthenticatedSocket } from './index.js';
import * as messageService from '../services/message.service.js';

export function handleMessageEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('message:send', async (data: {
    channelId: string;
    encryptedContent: string;
    contentNonce: string;
    idempotencyKey: string;
    refMessageId?: string;
    deviceId?: string;
  }) => {
    try {
      const message = await messageService.createMessage(
        data.channelId,
        socket.userId!,
        data.deviceId || 'unknown',
        data.encryptedContent,
        data.contentNonce,
        data.idempotencyKey,
        data.refMessageId,
      );

      // Broadcast to channel
      io.to(`channel:${data.channelId}`).emit('message:new', { message });
    } catch (err: any) {
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('message:edit', async (data: {
    messageId: string;
    channelId: string;
    encryptedContent: string;
    contentNonce: string;
  }) => {
    try {
      const message = await messageService.editMessage(
        data.messageId,
        socket.userId!,
        data.encryptedContent,
        data.contentNonce,
      );

      io.to(`channel:${data.channelId}`).emit('message:edited', { message });
    } catch (err: any) {
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('message:delete', async (data: {
    messageId: string;
    channelId: string;
  }) => {
    try {
      await messageService.deleteMessage(data.messageId, socket.userId!);
      io.to(`channel:${data.channelId}`).emit('message:deleted', {
        messageId: data.messageId,
        channelId: data.channelId,
      });
    } catch (err: any) {
      socket.emit('error', { message: err.message });
    }
  });
}
