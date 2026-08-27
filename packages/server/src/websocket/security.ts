import type { Socket } from 'socket.io';
import { getChannelAuthorization } from '../middleware/rbac.js';
import { isSessionActive } from '../security/session.js';

const DEFAULT_MAX_RATE_ENTRIES = 20_000;
const DEFAULT_MAX_SOCKETS_PER_USER = 16;
const DEFAULT_MAX_SOCKETS_TOTAL = 2_048;
const DEFAULT_MAX_PENDING_HANDSHAKES_PER_SOURCE = 8;
const DEFAULT_MAX_PENDING_HANDSHAKES_TOTAL = 256;
const DEFAULT_MAX_HANDSHAKE_ATTEMPTS_PER_SOURCE = 120;
const HANDSHAKE_ATTEMPT_WINDOW_MS = 60_000;

interface SharedRateEntry {
  count: number;
  resetAt: number;
  max: number;
  windowMs: number;
}

export interface SingleNodeSocketSecurityLimits {
  maxRateEntries: number;
  maxSocketsPerUser: number;
  maxSocketsTotal: number;
  maxPendingHandshakesPerSource: number;
  maxPendingHandshakesTotal: number;
}

/**
 * Bounded in-process state for the documented single-node deployment. A
 * multi-process deployment must replace this with an atomic shared backend.
 */
export class SingleNodeSocketSecurityState {
  private readonly limits: SingleNodeSocketSecurityLimits;
  private readonly rates = new Map<string, SharedRateEntry>();
  private readonly socketOwners = new Map<string, string>();
  private readonly userSockets = new Map<string, Set<string>>();
  private readonly pendingHandshakeOwners = new Map<string, string>();
  private readonly sourceHandshakes = new Map<string, Set<string>>();

  constructor(limits: Partial<SingleNodeSocketSecurityLimits> = {}) {
    this.limits = {
      maxRateEntries: limits.maxRateEntries ?? DEFAULT_MAX_RATE_ENTRIES,
      maxSocketsPerUser: limits.maxSocketsPerUser ?? DEFAULT_MAX_SOCKETS_PER_USER,
      maxSocketsTotal: limits.maxSocketsTotal ?? DEFAULT_MAX_SOCKETS_TOTAL,
      maxPendingHandshakesPerSource: limits.maxPendingHandshakesPerSource ?? DEFAULT_MAX_PENDING_HANDSHAKES_PER_SOURCE,
      maxPendingHandshakesTotal: limits.maxPendingHandshakesTotal ?? DEFAULT_MAX_PENDING_HANDSHAKES_TOTAL,
    };
    for (const value of Object.values(this.limits)) {
      if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Invalid socket security limit');
    }
  }

  consumeRate(userId: string, bucket: string, max: number, windowMs: number, now = Date.now()): boolean {
    if (
      !userId
      || !bucket
      || !Number.isSafeInteger(max)
      || max <= 0
      || !Number.isSafeInteger(windowMs)
      || windowMs <= 0
      || !Number.isSafeInteger(now)
    ) return false;

    const key = `${userId}\0${bucket}`;
    let rate = this.rates.get(key);
    if (rate && (rate.resetAt <= now || rate.max !== max || rate.windowMs !== windowMs)) {
      rate = undefined;
      this.rates.delete(key);
    }
    if (!rate) {
      if (this.rates.size >= this.limits.maxRateEntries) this.pruneExpiredRates(now);
      if (this.rates.size >= this.limits.maxRateEntries) return false;
      const resetAt = now + windowMs;
      if (!Number.isSafeInteger(resetAt)) return false;
      rate = { count: 0, resetAt, max, windowMs };
      this.rates.set(key, rate);
    }
    if (rate.count >= max) return false;
    rate.count += 1;
    return true;
  }

  acquireSocket(userId: string, socketId: string): boolean {
    if (!userId || !socketId) return false;
    const owner = this.socketOwners.get(socketId);
    if (owner) return false;
    if (this.socketOwners.size >= this.limits.maxSocketsTotal) return false;

    const sockets = this.userSockets.get(userId) ?? new Set<string>();
    if (sockets.size >= this.limits.maxSocketsPerUser) return false;
    sockets.add(socketId);
    this.userSockets.set(userId, sockets);
    this.socketOwners.set(socketId, userId);
    return true;
  }

  releaseSocket(socketId: string): boolean {
    const userId = this.socketOwners.get(socketId);
    if (!userId) return false;
    this.socketOwners.delete(socketId);
    const sockets = this.userSockets.get(userId);
    sockets?.delete(socketId);
    if (sockets?.size === 0) this.userSockets.delete(userId);
    return true;
  }

  acquirePendingHandshake(source: string, connectionId: string): boolean {
    if (!source || !connectionId || this.pendingHandshakeOwners.has(connectionId)) return false;
    if (this.pendingHandshakeOwners.size >= this.limits.maxPendingHandshakesTotal) return false;
    const pending = this.sourceHandshakes.get(source) ?? new Set<string>();
    if (pending.size >= this.limits.maxPendingHandshakesPerSource) return false;
    pending.add(connectionId);
    this.sourceHandshakes.set(source, pending);
    this.pendingHandshakeOwners.set(connectionId, source);
    return true;
  }

  releasePendingHandshake(connectionId: string): boolean {
    const source = this.pendingHandshakeOwners.get(connectionId);
    if (!source) return false;
    this.pendingHandshakeOwners.delete(connectionId);
    const pending = this.sourceHandshakes.get(source);
    pending?.delete(connectionId);
    if (pending?.size === 0) this.sourceHandshakes.delete(source);
    return true;
  }

  private pruneExpiredRates(now: number): void {
    for (const [key, rate] of this.rates) {
      if (rate.resetAt <= now) this.rates.delete(key);
    }
  }
}

const singleNodeSocketSecurity = new SingleNodeSocketSecurityState();

export interface AuthenticatedSocket extends Socket {
  userId?: string;
  sessionId?: string;
  deviceId?: string | null;
  sessionTokenHash?: string;
}

export async function authorizeSocketChannel(socket: AuthenticatedSocket, channelId: string, permission: number) {
  if (!socket.userId || !socket.sessionId || !socket.sessionTokenHash) return null;
  if (!await isSessionActive({
    userId: socket.userId,
    sessionId: socket.sessionId,
    deviceId: socket.deviceId ?? null,
    tokenHash: socket.sessionTokenHash,
  })) return null;
  const authorization = await getChannelAuthorization(socket.userId, channelId);
  if (!authorization || (authorization.permissions & permission) !== permission) return null;
  return authorization;
}

export function consumeSocketRate(
  socket: AuthenticatedSocket,
  bucket: string,
  max: number,
  windowMs: number,
  state = singleNodeSocketSecurity,
): boolean {
  return socket.userId ? state.consumeRate(socket.userId, bucket, max, windowMs) : false;
}

export function acquireSocketLease(
  socket: Pick<AuthenticatedSocket, 'id' | 'userId'>,
  state = singleNodeSocketSecurity,
): (() => void) | null {
  if (!socket.userId || !state.acquireSocket(socket.userId, socket.id)) return null;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    state.releaseSocket(socket.id);
  };
}

export function acquirePendingHandshakeLease(
  connectionId: string,
  source: string | undefined,
  state = singleNodeSocketSecurity,
): (() => void) | null {
  if (!state.acquirePendingHandshake(source || 'unknown', connectionId)) return null;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    state.releasePendingHandshake(connectionId);
  };
}

export function consumePendingHandshakeAttempt(
  source: string | undefined,
  state = singleNodeSocketSecurity,
): boolean {
  return state.consumeRate(
    `source:${source || 'unknown'}`,
    'handshake-attempt',
    DEFAULT_MAX_HANDSHAKE_ATTEMPTS_PER_SOURCE,
    HANDSHAKE_ATTEMPT_WINDOW_MS,
  );
}
