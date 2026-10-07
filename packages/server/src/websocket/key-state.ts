import type { Server as SocketServer } from 'socket.io';
import { logError } from '../security/logger.js';
import { keyStateRecipients, visibleKeyChannelIds } from '../services/mls-group.service.js';

/**
 * Tell devices that a channel's group may need their package or a commit
 * (§5.6): the channel room, plus the user rooms of current viewers with an
 * eligible device, so members who are looking at another channel or
 * workspace also hear it. Runs after the change committed; best-effort.
 */
export async function emitChannelKeyState(
  io: SocketServer | undefined,
  channelIds: readonly string[],
): Promise<void> {
  if (!io || channelIds.length === 0) return;
  const ids = [...new Set(channelIds)];
  let recipients = new Map<string, string[]>();
  try {
    recipients = await keyStateRecipients(ids);
  } catch (error) {
    // The channel room still hears it; user rooms are only an addition.
    logError('websocket.key_state_recipients', error);
  }
  for (const channelId of ids) {
    const rooms = [
      `channel:${channelId}`,
      ...(recipients.get(channelId) ?? []).map((userId) => `user:${userId}`),
    ];
    io.to(rooms).emit('channel:key-rotation-required', { channelId });
  }
}

/** A device or recovery approval: the user's devices check every channel they see. */
export async function emitUserKeyState(
  io: SocketServer | undefined,
  userId: string,
  workspaceIds: readonly string[],
): Promise<void> {
  if (!io || workspaceIds.length === 0) return;
  try {
    for (const channelId of await visibleKeyChannelIds(userId, workspaceIds)) {
      io.to(`user:${userId}`).emit('channel:key-rotation-required', { channelId });
    }
  } catch (error) {
    logError('websocket.key_state_user', error);
  }
}

/** A user joined a workspace: members may add the user's devices to the channels it sees. */
export async function emitJoinedWorkspaceKeyState(
  io: SocketServer | undefined,
  userId: string,
  workspaceId: string,
): Promise<void> {
  if (!io) return;
  try {
    await emitChannelKeyState(io, await visibleKeyChannelIds(userId, [workspaceId]));
  } catch (error) {
    logError('websocket.key_state_join', error);
  }
}

/** Channels whose viewer change makes a package or a commit due. */
export function keyStateChannelIds(
  effects: ReadonlyArray<{ channelId: string; gainedUserIds: readonly string[]; rotationRequired: boolean }>,
): string[] {
  return effects
    .filter((effect) => effect.rotationRequired || effect.gainedUserIds.length > 0)
    .map((effect) => effect.channelId);
}
