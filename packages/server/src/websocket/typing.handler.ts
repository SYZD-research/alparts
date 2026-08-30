import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { logError } from '../security/logger.js';
import { authorizeSocketChannel, consumeSocketRate, type AuthenticatedSocket } from './security.js';

const schema = z.object({ channelId: z.string().uuid() }).strict();

export function handleTypingEvents(_io: SocketServer, socket: AuthenticatedSocket) {
  const emit = async (data: unknown, isTyping: boolean) => {
    if (!consumeSocketRate(socket, 'typing', 90, 60_000)) return;
    const parsed = schema.safeParse(data);
    if (!parsed.success || !socket.rooms.has(`channel:${parsed.data.channelId}`)) return;
    if (!await authorizeSocketChannel(socket, parsed.data.channelId, Permissions.VIEW_CHANNELS)) return;
    socket.to(`channel:${parsed.data.channelId}`).emit('typing:update', {
      channelId: parsed.data.channelId,
      userId: socket.userId,
      isTyping,
    });
  };
  const safelyEmit = (data: unknown, isTyping: boolean) => {
    void emit(data, isTyping).catch((error) => logError('websocket.typing_update', error));
  };
  socket.on('typing:start', (data: unknown) => safelyEmit(data, true));
  socket.on('typing:stop', (data: unknown) => safelyEmit(data, false));
}
