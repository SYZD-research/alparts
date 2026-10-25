import type { Server as SocketServer } from 'socket.io';
import { emitJoinedWorkspaceKeyState } from './key-state.js';
import { joinAuthorizedUserToWorkspaceRoom } from './room-membership.js';

/**
 * A user joined a workspace, by accepting an invitation or by registering
 * with one. Members reload who is in it (mentions, member list), and their
 * devices may add the user's devices to the channels it sees. Runs after the
 * membership committed.
 */
export async function announceWorkspaceJoin(
  io: SocketServer | undefined,
  userId: string,
  workspaceId: string,
): Promise<void> {
  if (io) await joinAuthorizedUserToWorkspaceRoom(io, userId, workspaceId);
  io?.to(`workspace:${workspaceId}`).emit('workspace:member-added', { workspaceId, userId });
  void emitJoinedWorkspaceKeyState(io, userId, workspaceId);
}

/**
 * Channels or categories of a workspace were added, changed or removed.
 * Members reload the list, which the server filters by what each may see, so
 * the event names no channel: a private one stays unknown to the rest.
 */
export function emitWorkspaceChannelsChanged(io: SocketServer | undefined, workspaceId: string): void {
  io?.to(`workspace:${workspaceId}`).emit('workspace:channels-changed', { workspaceId });
}
