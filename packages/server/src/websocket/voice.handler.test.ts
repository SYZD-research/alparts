import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

const { VoiceParticipantRegistry, VoiceSignalingHub, parseVoiceSignal } = await import('./voice.handler.js');
const { voicePresenceRoom } = await import('./voice-rooms.js');

const channelA = '00000000-0000-4000-8000-000000000001';
const channelB = '00000000-0000-4000-8000-000000000002';
const deviceA = '00000000-0000-4000-8000-000000000011';
const deviceB = '00000000-0000-4000-8000-000000000012';

describe('bounded voice participant registry', () => {
  it('bounds a channel, routes only current peers, and removes moved sockets', () => {
    const registry = new VoiceParticipantRegistry(2);
    const first = registry.join(
      'socket_a', 'user-a', deviceA, channelA,
      new Date('2026-08-27T00:00:00Z'), 'participant_a',
    );
    assert.equal(first.joined, true);
    assert.deepEqual(first.existing, []);
    const second = registry.join(
      'socket_b', 'user-b', deviceB, channelA,
      new Date('2026-08-27T00:00:01Z'), 'participant_b',
    );
    assert.deepEqual(second.existing.map((entry) => entry.participantId), ['participant_a']);
    assert.equal(registry.canRoute('socket_a', 'participant_b', channelA), true);
    assert.equal(registry.canRoute('socket_a', 'participant_a', channelA), false);
    const duplicate = registry.join('socket_a', 'user-a', deviceA, channelA);
    assert.equal(duplicate.joined, false);
    assert.equal(duplicate.participant.participantId, 'participant_a');
    assert.deepEqual(duplicate.existing.map((entry) => entry.participantId), ['participant_b']);
    assert.throws(
      () => registry.join('socket_c', 'user-c', '00000000-0000-4000-8000-000000000013', channelA),
      /VOICE_CHANNEL_FULL/,
    );

    const moved = registry.join('socket_a', 'user-a', deviceA, channelB, new Date(), 'participant_a_moved');
    assert.equal(moved.previous?.channelId, channelA);
    assert.equal(registry.canRoute('socket_a', 'participant_b', channelA), false);
    assert.deepEqual(registry.list(channelA).map((entry) => entry.participantId), ['participant_b']);
    assert.deepEqual(registry.list(channelB).map((entry) => entry.participantId), ['participant_a_moved']);

    registry.rollbackJoin('socket_a', moved.previous);
    assert.deepEqual(registry.list(channelA).map((entry) => entry.participantId), ['participant_a', 'participant_b']);
    assert.deepEqual(registry.list(channelB), []);
  });

  it('never reports a muted participant as speaking', () => {
    const registry = new VoiceParticipantRegistry();
    registry.join('socket_a', 'user-a', deviceA, channelA, new Date(), 'participant_a');
    assert.deepEqual(registry.update('socket_a', channelA, { muted: true, speaking: true }), {
      participantId: 'participant_a',
      userId: 'user-a',
      deviceId: deviceA,
      muted: true,
      speaking: false,
      joinedAt: registry.get('socket_a')!.joinedAt,
    });
    assert.equal(registry.update('socket_a', channelB, { muted: false, speaking: true }), null);
  });
});

describe('voice signaling admission', () => {
  it('accepts exact signed SDP shapes and rejects field confusion', () => {
    const valid = {
      type: 'voice-signal',
      signalId: '00000000-0000-4000-8000-000000000020',
      sequence: 1,
      channelId: channelA,
      senderParticipantId: 'socket_a',
      senderDeviceId: deviceA,
      targetParticipantId: 'socket_b',
      kind: 'offer',
      descriptionType: 'offer',
      sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB\r\n',
      candidate: null,
      sdpMid: null,
      sdpMLineIndex: null,
      usernameFragment: null,
      signature: `${'A'.repeat(86)}==`,
    };
    assert.equal(parseVoiceSignal(valid)?.envelope.kind, 'offer');
    assert.equal(parseVoiceSignal({ ...valid, targetParticipantId: '../room' }), null);
    assert.equal(parseVoiceSignal({ ...valid, kind: 'ice' }), null);
    assert.equal(parseVoiceSignal({ ...valid, sequence: 0 }), null);
    assert.equal(parseVoiceSignal({ ...valid, extra: true }), null);
    assert.equal(parseVoiceSignal({ ...valid, sdp: 'x'.repeat(32 * 1024 + 1) }), null);
  });
});

describe('voice presence watch', () => {
  it('does not list a channel whose presence room the socket left while later channels were checked', async () => {
    const handlers = new Map<string, (...args: any[]) => unknown>();
    const rooms = new Set<string>(['socket_w']);
    const socket = {
      id: 'socket_w',
      userId: 'user-w',
      connected: true,
      rooms,
      on: (event: string, handler: (...args: any[]) => unknown) => { handlers.set(event, handler); },
      once: () => undefined,
      join: async (room: string) => { rooms.add(room); },
      leave: async (room: string) => { rooms.delete(room); },
    };
    const io = {
      of: () => ({ adapter: { on: () => undefined } }),
      to: () => ({ emit: () => undefined }),
      sockets: { sockets: new Map() },
    };
    const registry = new VoiceParticipantRegistry();
    registry.join('socket_p', 'user-p', deviceA, channelA, new Date(), 'participant_p');
    const hub = new VoiceSignalingHub(io as never, registry, []);
    // The database check is replaced: access to channel A is revoked (its rooms
    // are left) while channel B is being checked.
    (hub as unknown as { joinPresenceUnderAuthorizationLock: unknown }).joinPresenceUnderAuthorizationLock = async (
      _socket: unknown,
      channelId: string,
    ) => {
      rooms.add(voicePresenceRoom(channelId));
      if (channelId === channelB) rooms.delete(voicePresenceRoom(channelA));
      return true;
    };
    hub.attach(socket as never);
    let reply: { ok: boolean; channels: Array<{ channelId: string; participants: unknown[] }> } | undefined;
    await handlers.get('voice:watch')!({ channelIds: [channelA, channelB] }, (result: typeof reply) => { reply = result; });
    assert.equal(reply?.ok, true);
    assert.deepEqual(reply?.channels.map((entry) => entry.channelId), [channelB]);
  });
});

const { attachVoiceSfuEvents } = await import('./voice.handler.js');

/** A socket that records its handlers and what it was sent. */
function fakeSocket(id: string, deviceId: string, rooms: string[]) {
  const handlers = new Map<string, (...args: any[]) => unknown>();
  const sent: Array<{ event: string; payload: unknown }> = [];
  const socket = {
    id,
    userId: `user-${id}`,
    deviceId,
    connected: true,
    rooms: new Set<string>([id, ...rooms]),
    on: (event: string, handler: (...args: any[]) => unknown) => { handlers.set(event, handler); },
    once: (event: string, handler: (...args: any[]) => unknown) => { handlers.set(event, handler); },
    join: async (room: string | string[]) => { for (const entry of [room].flat()) socket.rooms.add(entry); },
    leave: async (room: string) => { socket.rooms.delete(room); },
    emit: (event: string, payload: unknown) => { sent.push({ event, payload }); },
  };
  const call = async (event: string, payload: unknown) => new Promise<any>((resolve) => {
    void handlers.get(event)!(payload, resolve);
  });
  return { socket, handlers, sent, call };
}

function fakeIo(sockets: Array<ReturnType<typeof fakeSocket>>) {
  const leaveListeners: Array<(room: string, socketId: string) => void> = [];
  let connection: ((socket: unknown) => void) | null = null;
  const io = {
    of: () => ({ adapter: { on: (_event: string, listener: (room: string, socketId: string) => void) => { leaveListeners.push(listener); } } }),
    to: (socketId: string) => ({ emit: (event: string, payload: unknown) => sockets.find((entry) => entry.socket.id === socketId)?.sent.push({ event, payload }) }),
    on: (_event: string, listener: (socket: unknown) => void) => { connection = listener; },
    sockets: { sockets: new Map(sockets.map((entry) => [entry.socket.id, entry.socket])) },
  };
  return {
    io,
    connect: (entry: ReturnType<typeof fakeSocket>) => connection!(entry.socket),
    leaveRoom: (entry: ReturnType<typeof fakeSocket>, room: string) => {
      entry.socket.rooms.delete(room);
      for (const listener of leaveListeners) listener(room, entry.socket.id);
    },
  };
}

describe('calls through the media server', () => {
  const room = `channel:${channelA}`;
  const wrappedKey = 'A'.repeat(342) + '==';
  const keyMessage = {
    type: 'voice-key',
    sequence: 1,
    channelId: channelA,
    senderParticipantId: 'participant_a',
    senderDeviceId: deviceA,
    targetParticipantId: 'participant_b',
    targetDeviceId: deviceB,
    keyId: 0xffff_ffff,
    wrappedKey,
    signature: `${'A'.repeat(86)}==`,
  };

  function call(options: { sfu: boolean }) {
    const a = fakeSocket('socket_a', deviceA, [room]);
    const b = fakeSocket('socket_b', deviceB, [room]);
    const { io, connect, leaveRoom } = fakeIo([a, b]);
    const registry = new VoiceParticipantRegistry();
    registry.join('socket_a', 'user-a', deviceA, channelA, new Date(), 'participant_a');
    registry.join('socket_b', 'user-b', deviceB, channelA, new Date(), 'participant_b');
    const hub = new VoiceSignalingHub(io as never, registry, []);
    if (options.sfu) hub.enableSfu();
    hub.attach(a.socket as never);
    hub.attach(b.socket as never);
    return { a, b, io, connect, leaveRoom, hub, registry };
  }

  it('relays a key message only between two current participants of the same call', async () => {
    const { a, b } = call({ sfu: true });
    assert.deepEqual(await a.call('voice:key', keyMessage), { ok: true });
    const delivered = b.sent.find((entry) => entry.event === 'voice:key')?.payload as { envelope: Record<string, unknown>; signature: string };
    assert.equal(delivered.signature, keyMessage.signature);
    const { signature: _signature, ...envelope } = keyMessage;
    assert.deepEqual(delivered.envelope, envelope);
    for (const refused of [
      { ...keyMessage, senderParticipantId: 'participant_b' },
      { ...keyMessage, senderDeviceId: deviceB },
      { ...keyMessage, targetDeviceId: deviceA },
      { ...keyMessage, channelId: channelB },
      { ...keyMessage, targetParticipantId: 'participant_x' },
      { ...keyMessage, keyId: 0x1_0000_0000 },
      { ...keyMessage, wrappedKey: 'A'.repeat(100) },
      { ...keyMessage, extra: true },
    ]) {
      assert.deepEqual(await a.call('voice:key', refused), { ok: false });
    }
    b.socket.rooms.delete(room);
    assert.deepEqual(await a.call('voice:key', keyMessage), { ok: false });
  });

  it('relays no key messages for direct calls, and no direct signals through the media server', async () => {
    const direct = call({ sfu: false });
    assert.deepEqual(await direct.a.call('voice:key', keyMessage), { ok: false });
    const media = call({ sfu: true });
    const signal = {
      type: 'voice-signal', signalId: '00000000-0000-4000-8000-000000000020', sequence: 1, channelId: channelA,
      senderParticipantId: 'participant_a', senderDeviceId: deviceA, targetParticipantId: 'participant_b',
      kind: 'offer', descriptionType: 'offer', sdp: 'v=0\r\n', candidate: null, sdpMid: null, sdpMLineIndex: null,
      usernameFragment: null, signature: `${'A'.repeat(86)}==`,
    };
    assert.deepEqual(await media.a.call('voice:signal', signal), { ok: false });
  });

  it('joins with the participant id the client chose, which a call through the media server requires', async () => {
    const c = fakeSocket('socket_c', '00000000-0000-4000-8000-000000000013', []);
    const { io } = fakeIo([c]);
    const hub = new VoiceSignalingHub(io as never, new VoiceParticipantRegistry(), []);
    hub.enableSfu();
    (hub as unknown as { joinUnderAuthorizationLock: unknown }).joinUnderAuthorizationLock = async () => {
      c.socket.rooms.add(room);
      return true;
    };
    hub.attach(c.socket as never);
    assert.deepEqual(await c.call('voice:join', { channelId: channelA }), { ok: false, error: 'INVALID_REQUEST' });
    const chosen = '00000000-0000-4000-8000-0000000000c3';
    const joined = await c.call('voice:join', { channelId: channelA, participantId: chosen });
    assert.equal(joined.ok, true);
    assert.equal(joined.self.participantId, chosen);
    assert.equal(joined.media, 'sfu');
  });

  it('gives media only to the call participant of the socket, under its id, and ends it with the call', async () => {
    const { a, b, io, connect, leaveRoom, hub } = call({ sfu: true });
    const outsider = fakeSocket('socket_o', '00000000-0000-4000-8000-000000000014', [room]);
    const coordinator = {
      joined: [] as string[],
      left: [] as string[],
      producers: [] as Array<{ participantId: string; producerId: string }>,
      async joinParticipant(_channelId: string, participantId: string) { this.joined.push(participantId); return { codecs: [] }; },
      leaveParticipant(participantId: string) { this.left.push(participantId); },
      getProducers() { return this.producers; },
      async createProducer(_channelId: string, participantId: string) {
        const producerId = `producer-${participantId}`;
        this.producers.push({ participantId, producerId });
        return producerId;
      },
      async createTransport() { return { id: 'transport', iceParameters: {}, iceCandidates: [], dtlsParameters: {} }; },
    };
    attachVoiceSfuEvents(io as never, coordinator as never, hub, async () => true);
    connect(a);
    connect(b);
    connect(outsider);
    assert.deepEqual(await outsider.call('voice:sfu:join', { channelId: channelA }), { ok: false, error: 'FORBIDDEN' });
    const joinedA = await a.call('voice:sfu:join', { channelId: channelA });
    assert.equal(joinedA.ok, true);
    assert.equal(joinedA.participantId, 'participant_a');
    assert.deepEqual(await a.call('voice:sfu:produce', { channelId: channelA, rtpParameters: { codecs: [] } }), { ok: true, producerId: 'producer-participant_a' });
    const joinedB = await b.call('voice:sfu:join', { channelId: channelA });
    // B learns of A's stream from the join, and A of B's when B starts sending.
    assert.deepEqual(joinedB.producers, [{ participantId: 'participant_a', producerId: 'producer-participant_a' }]);
    await b.call('voice:sfu:produce', { channelId: channelA, rtpParameters: { codecs: [] } });
    assert.deepEqual(a.sent.filter((entry) => entry.event === 'voice:sfu:producer').map((entry) => entry.payload), [
      { channelId: channelA, participantId: 'participant_b', producerId: 'producer-participant_b' },
    ]);
    // Media parameters are bounded before they reach the media server.
    assert.deepEqual(await a.call('voice:sfu:transport', { channelId: channelA, direction: 'sideways' }), { ok: false });
    assert.deepEqual(await a.call('voice:sfu:produce', { channelId: channelA, rtpParameters: { blob: 'x'.repeat(17 * 1024) } }), { ok: false });
    // Leaving the call (the channel room) ends the media session.
    leaveRoom(a, room);
    assert.deepEqual(coordinator.left, ['participant_a']);
    assert.deepEqual(await a.call('voice:sfu:transport', { channelId: channelA, direction: 'send' }), { ok: false });
  });
});
