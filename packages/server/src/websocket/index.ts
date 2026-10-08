import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { channels, workspaceMembers } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { readCookie } from '../security/cookies.js';
import { logError, logInfo } from '../security/logger.js';
import { isSessionActive, verifySessionToken } from '../security/session.js';
import { handleMessageEvents } from './message.handler.js';
import { handlePresenceEvents, syncPresence } from './presence.handler.js';
import { handleTypingEvents } from './typing.handler.js';
import {
  acquirePendingHandshakeLease,
  acquireSocketLease,
  consumePendingHandshakeAttempt,
  consumeSocketRate,
  type AuthenticatedSocket,
} from './security.js';
import { updateLastActive, getDeviceById } from '../services/device.service.js';
import {
  getChannelAuthorizationFromStore,
  getWorkspaceAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
} from '../services/authorization.service.js';
import { VoiceSignalingHub } from './voice.handler.js';
import { MAX_WORKSPACE_MEMBERSHIPS_PER_USER } from '../security/limits.js';
import { rateLimitSource, reportUntrustedForwarding, requestClientAddress } from '../security/client-address.js';
import { VoiceCoordinator } from '../voice/voice-coordinator.js';
import { attachVoiceSfuEvents } from './voice.handler.js';

const channelIdSchema = z.string().uuid();
const maxTimerDelayMs = 2_147_000_000;

interface ExpiringSocket {
  connected: boolean;
  disconnect(close?: boolean): unknown;
  once(event: 'disconnect', listener: () => void): unknown;
}

interface RoomJoinSocket {
  connected: boolean;
  join(room: string): void | Promise<void>;
  leave(room: string): void | Promise<void>;
  disconnect(close?: boolean): unknown;
}

type AuthorizationStore = Parameters<typeof lockWorkspaceForAuthorization>[0];

export async function joinRoomUnderWorkspaceAuthorizationLock(
  socket: RoomJoinSocket,
  room: string,
  withAuthorizationLock: (operation: (store: AuthorizationStore) => Promise<void>) => Promise<void>,
  isAuthorized: (store: AuthorizationStore) => Promise<boolean>,
): Promise<boolean> {
  let joined = false;
  try {
    await withAuthorizationLock(async (store) => {
      if (!socket.connected || !await isAuthorized(store) || !socket.connected) return;
      await socket.join(room);
      joined = true;
    });
    return joined;
  } catch (error) {
    if (joined) {
      try {
        await socket.leave(room);
      } catch {
        socket.disconnect(true);
      }
    }
    throw error;
  }
}

export function scheduleSessionExpiry(socket: ExpiringSocket, expiresAtMs: number): void {
  let timer: NodeJS.Timeout | undefined;
  const clearTimer = () => {
    if (timer) clearTimeout(timer);
    timer = undefined;
  };
  const expireOrReschedule = () => {
    const remaining = expiresAtMs - Date.now();
    if (remaining <= 0) {
      clearTimer();
      if (socket.connected) socket.disconnect(true);
      return;
    }
    timer = setTimeout(expireOrReschedule, Math.min(remaining, maxTimerDelayMs));
    timer.unref();
  };
  socket.once('disconnect', clearTimer);
  expireOrReschedule();
}

export function setupWebSocket(io: SocketServer) {
  const voiceSignaling = new VoiceSignalingHub(io);
  io.use(async (socket: AuthenticatedSocket, next) => {
    const cookieToken = readCookie(socket.handshake.headers.cookie, config.auth.cookieName);
    const origin = socket.handshake.headers.origin;
    // Browser WebSocket handshakes are not protected by the Fetch CORS
    // response policy. Enforce the same exact-origin boundary as REST before
    // accepting a cookie-authenticated socket. Token-authenticated native
    // clients may omit Origin, but cannot claim an unapproved browser origin.
    if (!isSocketHandshakeOriginAllowed(origin, Boolean(cookieToken))) {
      next(new Error('Origin not allowed'));
      return;
    }
    const authToken = typeof socket.handshake.auth?.token === 'string' && socket.handshake.auth.token.length <= 4096
      ? socket.handshake.auth.token
      : null;
    // Behind a reverse proxy every peer address is the proxy; count clients.
    reportUntrustedForwarding(socket.request);
    const source = rateLimitSource(requestClientAddress(socket.request));
    if (!consumePendingHandshakeAttempt(source)) {
      next(new Error('Connection rate exceeded'));
      return;
    }
    const releasePendingHandshake = acquirePendingHandshakeLease(socket.id, source);
    if (!releasePendingHandshake) {
      next(new Error('Connection limit exceeded'));
      return;
    }
    let releaseSocketLease: (() => void) | null = null;
    try {
      const token = cookieToken || authToken || '';
      const session = await verifySessionToken(token);
      if (!session) {
        next(new Error('Authentication required'));
        return;
      }
      const device = session.deviceId ? await getDeviceById(session.deviceId) : null;
      if (!device || device.userId !== session.userId || !device.approvedAt || device.revokedAt) { next(new Error('Device approval required')); return; }
      socket.userId = session.userId;
      socket.sessionId = session.sessionId;
      socket.deviceId = session.deviceId;
      socket.sessionTokenHash = session.tokenHash;
      socket.data.sessionExpiresAt = session.expiresAtMs;
      releaseSocketLease = acquireSocketLease(socket);
      if (!releaseSocketLease) {
        next(new Error('Connection limit exceeded'));
        return;
      }
      socket.once('disconnect', releaseSocketLease);
      socket.conn.once('close', releaseSocketLease);
      if (session.deviceId) void updateLastActive(session.deviceId).catch(() => undefined);
      next();
    } catch {
      releaseSocketLease?.();
      next(new Error('Authentication required'));
    } finally {
      releasePendingHandshake();
    }
  });

  io.on('connection', async (socket: AuthenticatedSocket) => {
    logInfo('websocket.connected');
    const sessionExpiresAt = socket.data.sessionExpiresAt;
    if (typeof sessionExpiresAt !== 'number' || sessionExpiresAt <= Date.now()) {
      socket.disconnect(true);
      return;
    }
    scheduleSessionExpiry(socket, sessionExpiresAt);
    let identityRoomsReady: Promise<void>;
    try {
      identityRoomsReady = Promise.resolve(socket.join([`user:${socket.userId}`, `session:${socket.sessionId}`]));
    } catch (error) {
      logError('websocket.identity_rooms', error);
      socket.disconnect(true);
      return;
    }

    // Register listeners before the first database await. Otherwise a fast
    // client can emit channel:join immediately after `connect` and lose the
    // event while workspace-room hydration is still in flight.
    socket.on('channel:join', async (value: unknown, acknowledge?: (result: { ok: boolean }) => void) => {
      try {
        await identityRoomsReady;
        if (!consumeSocketRate(socket, 'channel-membership', 60, 60_000)) return acknowledge?.({ ok: false });
        const channelId = channelIdSchema.parse(value);
        acknowledge?.({ ok: await joinAuthorizedChannelRoom(socket, channelId, Permissions.VIEW_CHANNELS) });
      } catch {
        acknowledge?.({ ok: false });
      }
    });

    socket.on('channel:leave', (value: unknown) => {
      const parsed = channelIdSchema.safeParse(value);
      if (parsed.success) {
        void Promise.resolve(socket.leave(`channel:${parsed.data}`))
          .catch((error) => logError('websocket.channel_leave', error));
      }
    });

    handleMessageEvents(io, socket);
    handlePresenceEvents(io, socket);
    handleTypingEvents(io, socket);
    voiceSignaling.attach(socket);

    socket.on('disconnect', async () => {
      logInfo('websocket.disconnected');
      try {
        await syncPresence(io, socket.userId!);
      } catch (error) {
        logError('websocket.disconnect_presence', error);
      }
    });

    try {
      await identityRoomsReady;
      if (!socket.connected) return;
      // The socket is now counted in its user room; publish "online" if this
      // is the user's first live connection.
      void syncPresence(io, socket.userId!).catch((error) => logError('websocket.connect_presence', error));
      const memberships = await db.query.workspaceMembers.findMany({
        columns: { workspaceId: true },
        where: eq(workspaceMembers.userId, socket.userId!),
        limit: MAX_WORKSPACE_MEMBERSHIPS_PER_USER + 1,
      });
      if (memberships.length > MAX_WORKSPACE_MEMBERSHIPS_PER_USER) {
        throw new Error('WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED');
      }
      for (const membership of memberships) {
        if (!socket.connected) return;
        await joinRoomUnderWorkspaceAuthorizationLock(
          socket,
          `workspace:${membership.workspaceId}`,
          async (operation) => db.transaction(async (transaction) => {
            await lockWorkspaceForAuthorization(transaction, membership.workspaceId, 'share');
            await operation(transaction);
          }),
          async (transaction) => {
            const authorization = await getWorkspaceAuthorizationFromStore(
              transaction,
              membership.workspaceId,
              socket.userId!,
            );
            return Boolean(authorization
              && (authorization.permissionMask & Permissions.VIEW_CHANNELS) === Permissions.VIEW_CHANNELS);
          },
        );
      }
    } catch (error) {
      logError('websocket.room_hydration', error);
      socket.disconnect(true);
    }
  });
}

async function joinAuthorizedChannelRoom(socket: AuthenticatedSocket, channelId: string, permission: number): Promise<boolean> {
  const userId = socket.userId;
  if (!userId || !socket.sessionId || !socket.sessionTokenHash || !await isSessionActive({
    userId,
    sessionId: socket.sessionId,
    deviceId: socket.deviceId ?? null,
    tokenHash: socket.sessionTokenHash,
  })) return false;

  const channel = await db.query.channels.findFirst({
    columns: { workspaceId: true },
    where: eq(channels.id, channelId),
  });
  if (!channel) return false;

  return joinRoomUnderWorkspaceAuthorizationLock(
    socket,
    `channel:${channelId}`,
    async (operation) => db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, channel.workspaceId, 'share');
      await operation(transaction);
    }),
    async (transaction) => {
      const authorization = await getChannelAuthorizationFromStore(transaction, userId, channelId);
      return authorization?.workspaceId === channel.workspaceId
        && isVisibleChannelAuthorization(authorization)
        && (authorization.permissions & permission) === permission;
    },
  );
}

export function isSocketHandshakeOriginAllowed(origin: string | undefined, hasSessionCookie: boolean): boolean {
  if (origin !== undefined && !config.cors.origins.includes(origin)) return false;
  return !hasSessionCookie || origin !== undefined;
}

export async function startVoiceSfu(
	io: SocketServer,
): Promise<VoiceCoordinator | null> {
	const sfu = config.voice.sfu;

	if (!sfu.enabled) {
		return null;
	}

	const coordinator = new VoiceCoordinator({
		bindAddress: sfu.bindAddress,
		announcedAddress: sfu.announcedAddress,
		basePort: sfu.basePort,
		workerCount: sfu.workerCount,
	});

	try {
		await coordinator.start();
		attachVoiceSfuEvents(io, coordinator);
	} catch (error) {
		await coordinator.close();
		throw error;
	}

	logInfo('voice.sfu_started', {
		workerCount: sfu.workerCount,
		basePort: sfu.basePort,
	});

	return coordinator;
}


export type { AuthenticatedSocket } from './security.js';
