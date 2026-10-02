import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

describe('WebSocket session expiry', () => {
  it('disconnects an idle socket at the effective session expiry', async () => {
    const { scheduleSessionExpiry } = await import('./index.js');
    let disconnectListener: (() => void) | undefined;
    let disconnectCalls = 0;
    let forced = false;
    const socket = {
      connected: true,
      disconnect(close?: boolean) {
        disconnectCalls += 1;
        forced = close === true;
        this.connected = false;
        disconnectListener?.();
        return this;
      },
      once(event: 'disconnect', listener: () => void) {
        assert.equal(event, 'disconnect');
        disconnectListener = listener;
        return this;
      },
    };

    scheduleSessionExpiry(socket, Date.now() + 20);
    await delay(60);

    assert.equal(disconnectCalls, 1);
    assert.equal(forced, true);
    assert.equal(socket.connected, false);
  });

  it('clears the expiry timer when the socket disconnects early', async () => {
    const { scheduleSessionExpiry } = await import('./index.js');
    let disconnectListener: (() => void) | undefined;
    let disconnectCalls = 0;
    const socket = {
      connected: true,
      disconnect() {
        disconnectCalls += 1;
        this.connected = false;
        disconnectListener?.();
        return this;
      },
      once(_event: 'disconnect', listener: () => void) {
        disconnectListener = listener;
        return this;
      },
    };

    scheduleSessionExpiry(socket, Date.now() + 30);
    socket.disconnect();
    await delay(60);

    assert.equal(disconnectCalls, 1);
  });
});

describe('WebSocket origin boundary', () => {
  it('requires an exact allowed Origin for cookie-authenticated browser sockets', async () => {
    const { isSocketHandshakeOriginAllowed } = await import('./index.js');

    assert.equal(isSocketHandshakeOriginAllowed('http://localhost:5173', true), true);
    assert.equal(isSocketHandshakeOriginAllowed(undefined, true), false);
    assert.equal(isSocketHandshakeOriginAllowed('https://evil.example', true), false);
    assert.equal(isSocketHandshakeOriginAllowed('http://localhost:5173.evil.example', true), false);
  });

  it('allows an Origin-less explicit-token client but rejects a forged browser Origin', async () => {
    const { isSocketHandshakeOriginAllowed } = await import('./index.js');

    assert.equal(isSocketHandshakeOriginAllowed(undefined, false), true);
    assert.equal(isSocketHandshakeOriginAllowed('http://localhost:5173', false), true);
    assert.equal(isSocketHandshakeOriginAllowed('https://evil.example', false), false);
  });
});

describe('single-node WebSocket budgets', () => {
  it('shares each named rate budget across sockets for the same user', async () => {
    const { SingleNodeSocketSecurityState, consumeSocketRate } = await import('./security.js');
    const state = new SingleNodeSocketSecurityState({ maxRateEntries: 8 });
    const firstSocket = { userId: 'user-a' } as any;
    const secondSocket = { userId: 'user-a' } as any;

    assert.equal(consumeSocketRate(firstSocket, 'message-write', 2, 60_000, state), true);
    assert.equal(consumeSocketRate(secondSocket, 'message-write', 2, 60_000, state), true);
    assert.equal(consumeSocketRate(firstSocket, 'message-write', 2, 60_000, state), false);
    assert.equal(consumeSocketRate(secondSocket, 'presence', 1, 60_000, state), true);
    assert.equal(consumeSocketRate({ userId: 'user-b' } as any, 'message-write', 2, 60_000, state), true);

    const bounded = new SingleNodeSocketSecurityState({ maxRateEntries: 1 });
    assert.equal(bounded.consumeRate('user-a', 'message-write', 1, 10, 100), true);
    assert.equal(bounded.consumeRate('user-b', 'message-write', 1, 10, 100), false);
    assert.equal(bounded.consumeRate('user-b', 'message-write', 1, 10, 111), true);
  });

  it('caps concurrent sockets and releases exactly one lease on disconnect', async () => {
    const { SingleNodeSocketSecurityState, acquireSocketLease } = await import('./security.js');
    const state = new SingleNodeSocketSecurityState({
      maxRateEntries: 8,
      maxSocketsPerUser: 2,
      maxSocketsTotal: 3,
    });
    const first = acquireSocketLease({ id: 'socket-1', userId: 'user-a' } as any, state);
    const second = acquireSocketLease({ id: 'socket-2', userId: 'user-a' } as any, state);

    assert.equal(typeof first, 'function');
    assert.equal(typeof second, 'function');
    assert.equal(acquireSocketLease({ id: 'socket-3', userId: 'user-a' } as any, state), null);
    const thirdUser = acquireSocketLease({ id: 'socket-3', userId: 'user-b' } as any, state);
    assert.equal(typeof thirdUser, 'function');
    assert.equal(acquireSocketLease({ id: 'socket-4', userId: 'user-c' } as any, state), null);
    first?.();
    first?.();
    const replacement = acquireSocketLease({ id: 'socket-4', userId: 'user-a' } as any, state);
    assert.equal(typeof replacement, 'function');
    second?.();
    thirdUser?.();
    replacement?.();
  });

  it('caps unauthenticated handshakes before database-backed token verification', async () => {
    const { SingleNodeSocketSecurityState, acquirePendingHandshakeLease } = await import('./security.js');
    const state = new SingleNodeSocketSecurityState({
      maxRateEntries: 8,
      maxPendingHandshakesPerSource: 1,
      maxPendingHandshakesTotal: 2,
    });
    const first = acquirePendingHandshakeLease('connection-1', '192.0.2.1', state);
    assert.equal(typeof first, 'function');
    assert.equal(acquirePendingHandshakeLease('connection-2', '192.0.2.1', state), null);
    const second = acquirePendingHandshakeLease('connection-2', '192.0.2.2', state);
    assert.equal(typeof second, 'function');
    assert.equal(acquirePendingHandshakeLease('connection-3', '192.0.2.3', state), null);
    first?.();
    first?.();
    assert.equal(typeof acquirePendingHandshakeLease('connection-3', '192.0.2.1', state), 'function');
    second?.();
  });

  it('rate-limits serial handshake attempts before session lookup', async () => {
    const { consumePendingHandshakeAttempt } = await import('./security.js');
    const source = '198.51.100.42';
    for (let attempt = 0; attempt < 120; attempt += 1) {
      assert.equal(consumePendingHandshakeAttempt(source), true);
    }
    assert.equal(consumePendingHandshakeAttempt(source), false);
  });
});

describe('serialized WebSocket room joins', () => {
  it('does not apply a delayed server-side room grant after authorization was revoked', async () => {
    const { joinBroadcastRoomUnderWorkspaceAuthorizationLock } = await import('./room-membership.js');
    let joins = 0;
    let authorized = true;
    let releaseLock!: () => void;
    let reportWaiting!: () => void;
    const waiting = new Promise<void>((resolve) => { reportWaiting = resolve; });
    const lockGate = new Promise<void>((resolve) => { releaseLock = resolve; });

    const grant = joinBroadcastRoomUnderWorkspaceAuthorizationLock(
      () => { joins += 1; },
      async (operation) => {
        reportWaiting();
        await lockGate;
        await operation({});
      },
      async () => authorized,
    );
    await waiting;
    authorized = false;
    releaseLock();

    assert.equal(await grant, false);
    assert.equal(joins, 0);
  });

  it('applies a legitimate server-side room grant before releasing authorization lock', async () => {
    const { joinBroadcastRoomUnderWorkspaceAuthorizationLock } = await import('./room-membership.js');
    let lockHeld = false;
    let joins = 0;

    const joined = await joinBroadcastRoomUnderWorkspaceAuthorizationLock(
      () => {
        assert.equal(lockHeld, true);
        joins += 1;
      },
      async (operation) => {
        lockHeld = true;
        try {
          await operation({});
        } finally {
          lockHeld = false;
        }
      },
      async () => lockHeld,
    );

    assert.equal(joined, true);
    assert.equal(joins, 1);
    assert.equal(lockHeld, false);
  });

  it('rejects authorization that became stale before the workspace lock was acquired', async () => {
    const { joinRoomUnderWorkspaceAuthorizationLock } = await import('./index.js');
    const rooms: string[] = [];
    let authorized = true;
    let releaseLock!: () => void;
    let reportWaiting!: () => void;
    const waiting = new Promise<void>((resolve) => { reportWaiting = resolve; });
    const lockGate = new Promise<void>((resolve) => { releaseLock = resolve; });
    const socket = {
      connected: true,
      async join(room: string) { rooms.push(room); },
      async leave(room: string) { rooms.splice(rooms.indexOf(room), 1); },
      disconnect() { this.connected = false; },
    };

    const attempt = joinRoomUnderWorkspaceAuthorizationLock(
      socket,
      'channel:stale',
      async (operation) => {
        reportWaiting();
        await lockGate;
        await operation({});
      },
      async () => authorized,
    );
    await waiting;
    assert.equal(authorized, true, 'the pre-lock authorization snapshot was initially valid');
    authorized = false;
    releaseLock();

    assert.equal(await attempt, false);
    assert.deepEqual(rooms, []);
  });

  it('joins an authorized room before releasing the workspace lock', async () => {
    const { joinRoomUnderWorkspaceAuthorizationLock } = await import('./index.js');
    const rooms: string[] = [];
    let lockHeld = false;
    const socket = {
      connected: true,
      async join(room: string) {
        assert.equal(lockHeld, true);
        rooms.push(room);
      },
      async leave(room: string) { rooms.splice(rooms.indexOf(room), 1); },
      disconnect() { this.connected = false; },
    };

    const joined = await joinRoomUnderWorkspaceAuthorizationLock(
      socket,
      'channel:allowed',
      async (operation) => {
        lockHeld = true;
        try {
          await operation({});
        } finally {
          lockHeld = false;
        }
      },
      async () => {
        assert.equal(lockHeld, true);
        return true;
      },
    );

    assert.equal(joined, true);
    assert.deepEqual(rooms, ['channel:allowed']);
    assert.equal(lockHeld, false);
  });
});

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
