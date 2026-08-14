import { Server as SocketServer, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { config } from '../config/index.js';
import { handleMessageEvents } from './message.handler.js';
import { handlePresenceEvents } from './presence.handler.js';
import { handleTypingEvents } from './typing.handler.js';
import * as deviceService from '../services/device.service.js';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  sessionId?: string;
}

export function setupWebSocket(io: SocketServer) {
  // Auth middleware
  io.use((socket: AuthenticatedSocket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
      next(new Error('Authentication required'));
      return;
    }

    try {
      const payload = jwt.verify(token, config.jwt.secret) as { userId: string; sessionId: string };
      socket.userId = payload.userId;
      socket.sessionId = payload.sessionId;
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket: AuthenticatedSocket) => {
    console.log(`User connected: ${socket.userId}`);

    // Join user's personal room for notifications
    if (socket.userId) {
      socket.join(`user:${socket.userId}`);
    }

    // Handle channel join/leave
    socket.on('channel:join', (channelId: string) => {
      socket.join(`channel:${channelId}`);
    });

    socket.on('channel:leave', (channelId: string) => {
      socket.leave(`channel:${channelId}`);
    });

    // Setup event handlers
    handleMessageEvents(io, socket);
    handlePresenceEvents(io, socket);
    handleTypingEvents(io, socket);

    socket.on('disconnect', () => {
      console.log(`User disconnected: ${socket.userId}`);
      // Update presence to offline
      if (socket.userId) {
        io.emit('presence:changed', { userId: socket.userId, status: 'offline' });
      }
    });
  });
}

export type { AuthenticatedSocket };
