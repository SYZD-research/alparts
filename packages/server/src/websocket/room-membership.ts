import type { Server as SocketServer } from 'socket.io';
import { eq } from 'drizzle-orm';
import { Permissions } from '@alparts/shared';
import { db } from '../db/index.js';
import { channels } from '../db/schema.js';
import { logError } from '../security/logger.js';
import {
  getChannelAuthorizationFromStore,
  getWorkspaceAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
} from '../services/authorization.service.js';

type AuthorizationStore = Parameters<typeof lockWorkspaceForAuthorization>[0];

/**
 * Recheck a delayed room grant while holding the same workspace lock used by
 * membership/permission mutations, and perform the in-memory join before that
 * lock is released. This keeps post-commit realtime effects fail-closed.
 */
export async function joinBroadcastRoomUnderWorkspaceAuthorizationLock(
  joinRoom: () => void,
  withAuthorizationLock: (operation: (store: AuthorizationStore) => Promise<void>) => Promise<void>,
  isAuthorized: (store: AuthorizationStore) => Promise<boolean>,
): Promise<boolean> {
  let joined = false;
  await withAuthorizationLock(async (store) => {
    if (!await isAuthorized(store)) return;
    joinRoom();
    joined = true;
  });
  return joined;
}

export async function joinAuthorizedUserToWorkspaceRoom(
  io: SocketServer,
  userId: string,
  workspaceId: string,
): Promise<boolean> {
  try {
    return await joinBroadcastRoomUnderWorkspaceAuthorizationLock(
      () => io.in(`user:${userId}`).socketsJoin(`workspace:${workspaceId}`),
      async (operation) => db.transaction(async (transaction) => {
        await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
        await operation(transaction);
      }),
      async (transaction) => {
        const authorization = await getWorkspaceAuthorizationFromStore(transaction, workspaceId, userId);
        return Boolean(authorization
          && (authorization.permissionMask & Permissions.VIEW_CHANNELS) === Permissions.VIEW_CHANNELS);
      },
    );
  } catch (error) {
    logError('websocket.workspace_room_grant', error);
    return false;
  }
}

export async function joinAuthorizedUserToChannelRoom(
  io: SocketServer,
  userId: string,
  channelId: string,
): Promise<boolean> {
  try {
    const location = await db.query.channels.findFirst({
      columns: { workspaceId: true },
      where: eq(channels.id, channelId),
    });
    if (!location) return false;
    return await joinBroadcastRoomUnderWorkspaceAuthorizationLock(
      () => io.in(`user:${userId}`).socketsJoin(`channel:${channelId}`),
      async (operation) => db.transaction(async (transaction) => {
        await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
        await operation(transaction);
      }),
      async (transaction) => {
        const authorization = await getChannelAuthorizationFromStore(transaction, userId, channelId);
        return authorization?.workspaceId === location.workspaceId
          && isVisibleChannelAuthorization(authorization);
      },
    );
  } catch (error) {
    logError('websocket.channel_room_grant', error);
    return false;
  }
}
