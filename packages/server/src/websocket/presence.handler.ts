import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { users, workspaceMembers } from '../db/schema.js';
import { isSessionActive } from '../security/session.js';
import { consumeSocketRate, type AuthenticatedSocket } from './security.js';

const schema = z.object({ status: z.enum(['online', 'idle', 'dnd', 'offline']) }).strict();

export function handlePresenceEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('presence:update', async (data: unknown) => {
    const parsed = schema.safeParse(data);
    if (!parsed.success || !consumeSocketRate(socket, 'presence', 12, 60_000)) return;
    if (!socket.userId || !socket.sessionId || !socket.sessionTokenHash || !await isSessionActive({
      userId: socket.userId,
      sessionId: socket.sessionId,
      deviceId: socket.deviceId ?? null,
      tokenHash: socket.sessionTokenHash,
    })) return;
    await db.update(users).set({ status: parsed.data.status, updatedAt: new Date() }).where(eq(users.id, socket.userId));
    await emitPresenceToWorkspaces(io, socket.userId, parsed.data.status);
  });
}

export async function setOfflineIfLastConnection(io: SocketServer, userId: string) {
  const remaining = await io.in(`user:${userId}`).fetchSockets();
  if (remaining.length > 0) return;
  await db.update(users).set({ status: 'offline', updatedAt: new Date() }).where(eq(users.id, userId));
  await emitPresenceToWorkspaces(io, userId, 'offline');
}

async function emitPresenceToWorkspaces(io: SocketServer, userId: string, status: string) {
  const memberships = await db.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
  });
  for (const membership of memberships) {
    io.to(`workspace:${membership.workspaceId}`).emit('presence:changed', { userId, status });
  }
}
