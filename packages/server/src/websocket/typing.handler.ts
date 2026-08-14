import { Server as SocketServer } from 'socket.io';
import { AuthenticatedSocket } from './index.js';

export function handleTypingEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('typing:start', (data: { channelId: string }) => {
    socket.to(`channel:${data.channelId}`).emit('typing:update', {
      channelId: data.channelId,
      userId: socket.userId,
      isTyping: true,
    });
  });

  socket.on('typing:stop', (data: { channelId: string }) => {
    socket.to(`channel:${data.channelId}`).emit('typing:update', {
      channelId: data.channelId,
      userId: socket.userId,
      isTyping: false,
    });
  });
}
