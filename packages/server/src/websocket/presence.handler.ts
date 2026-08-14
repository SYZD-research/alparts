import { Server as SocketServer } from 'socket.io';
import { AuthenticatedSocket } from './index.js';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';

export function handlePresenceEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('presence:update', async (data: { status: string }) => {
    try {
      const validStatuses = ['online', 'idle', 'dnd', 'offline'];
      if (!validStatuses.includes(data.status)) return;

      await db.update(users)
        .set({ status: data.status, updatedAt: new Date() })
        .where(eq(users.id, socket.userId!));

      io.emit('presence:changed', {
        userId: socket.userId,
        status: data.status,
      });
    } catch (err) {
      console.error('Presence update error:', err);
    }
  });
}
