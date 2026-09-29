import type { Server as SocketServer } from 'socket.io';
import type { UserStatusType } from '@alparts/shared';
import { z } from 'zod';
import { eq, ne } from 'drizzle-orm';
import { db } from '../db/index.js';
import { users, workspaceMembers } from '../db/schema.js';
import { isSessionActive } from '../security/session.js';
import { MAX_WORKSPACE_MEMBERSHIPS_PER_USER } from '../security/limits.js';
import { logError } from '../security/logger.js';
import { consumeSocketRate, type AuthenticatedSocket } from './security.js';
import { PresenceSynchronizer } from './presence-sync.js';

const schema = z.object({ status: z.enum(['online', 'idle', 'dnd', 'offline']) }).strict();
const synchronizers = new WeakMap<SocketServer, PresenceSynchronizer>();

function presenceFor(io: SocketServer): PresenceSynchronizer {
  let synchronizer = synchronizers.get(io);
  if (!synchronizer) {
    synchronizer = new PresenceSynchronizer({
      countConnections: async (userId) => (await io.in(`user:${userId}`).fetchSockets()).length,
      readStatus: async (userId) => {
        const row = await db.query.users.findFirst({ columns: { status: true }, where: eq(users.id, userId) });
        return (row?.status as UserStatusType | undefined) ?? null;
      },
      writeStatus: async (userId, status) => {
        await db.update(users).set({ status, updatedAt: new Date() }).where(eq(users.id, userId));
      },
      broadcast: (userId, status) => emitPresenceToWorkspaces(io, userId, status),
    });
    synchronizers.set(io, synchronizer);
  }
  return synchronizer;
}

export function handlePresenceEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('presence:update', async (data: unknown) => {
    try {
      const parsed = schema.safeParse(data);
      if (!parsed.success || !consumeSocketRate(socket, 'presence', 12, 60_000)) return;
      if (!socket.userId || !socket.sessionId || !socket.sessionTokenHash || !await isSessionActive({
        userId: socket.userId,
        sessionId: socket.sessionId,
        deviceId: socket.deviceId ?? null,
        tokenHash: socket.sessionTokenHash,
      })) return;
      await presenceFor(io).choose(socket.userId, parsed.data.status);
    } catch (error) {
      logError('websocket.presence_update', error);
    }
  });
}

/** Call after a socket joined, or left, the user's identity room. */
export function syncPresence(io: SocketServer, userId: string): Promise<void> {
  return presenceFor(io).sync(userId);
}

/**
 * Connections do not survive a restart, and a crash skips disconnect
 * handlers. The runtime lease guarantees this is the only serving process.
 */
export async function resetPresenceAfterStartup(): Promise<void> {
  await db.update(users).set({ status: 'offline', updatedAt: new Date() }).where(ne(users.status, 'offline'));
}

async function emitPresenceToWorkspaces(io: SocketServer, userId: string, status: UserStatusType) {
  const memberships = await db.query.workspaceMembers.findMany({
    columns: { workspaceId: true },
    where: eq(workspaceMembers.userId, userId),
    limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
  });
  if (memberships.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
    throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
  }
  for (const membership of memberships) {
    io.to(`workspace:${membership.workspaceId}`).emit('presence:changed', { userId, status });
  }
}
