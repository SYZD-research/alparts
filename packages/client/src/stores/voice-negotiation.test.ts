import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { VoiceParticipant } from '@alparts/shared';
import { buildVoiceDescriptionEnvelope } from '../services/voice-signal-model';

const mocks = vi.hoisted(() => ({ socket: { connected: true, on: vi.fn(), off: vi.fn(), emit: vi.fn() },
  directory: vi.fn(), device: vi.fn(), sign: vi.fn(), verify: vi.fn() }));
vi.mock('../services/socket', () => ({ connectSocket: () => mocks.socket }));
vi.mock('../services/api', () => ({ api: { getChannelDeviceDirectory: mocks.directory } }));
vi.mock('../services/crypto.service', () => ({ getActiveDevice: mocks.device,
  signVoiceSignalEnvelope: mocks.sign, verifyVoiceSignalSignature: mocks.verify }));
import { useVoiceStore } from './voice.store';

const channelId = crypto.randomUUID();
const listeners = new Map<string, (value: unknown) => void>();
const signature = 'A'.repeat(86) + '==';
let self: VoiceParticipant;
let remote: VoiceParticipant;
const createdPeers: FakePeer[] = [];
let makeOffer: () => Promise<RTCSessionDescriptionInit>;
const participant = (id: string): VoiceParticipant => ({ participantId: id, userId: crypto.randomUUID(),
  deviceId: crypto.randomUUID(), muted: false, speaking: false, joinedAt: new Date().toISOString() });

class FakePeer {
  signalingState = 'stable';
  localDescription: RTCSessionDescriptionInit | null = null;
  remoteDescription: RTCSessionDescriptionInit | null = null;
  changes: string[] = [];
  constructor() { createdPeers.push(this); }
  addTrack() {}
  close() { this.signalingState = 'closed'; }
  createOffer() { return makeOffer(); }
  async createAnswer(): Promise<RTCSessionDescriptionInit> { return { type: 'answer', sdp: 'answer' }; }
  async setLocalDescription(value: RTCSessionDescriptionInit) {
    this.changes.push(`local:${value.type}`);
    this.localDescription = value.type === 'rollback' ? null : value;
    this.signalingState = value.type === 'offer' ? 'have-local-offer' : 'stable';
  }
  async setRemoteDescription(value: RTCSessionDescriptionInit) {
    if (value.type === 'offer') expect(this.signalingState).toBe('stable');
    this.changes.push(`remote:${value.type}`);
    this.remoteDescription = value;
    this.signalingState = value.type === 'offer' ? 'have-remote-offer' : 'stable';
  }
}

beforeEach(() => {
  vi.resetAllMocks();
  listeners.clear();
  createdPeers.length = 0;
  // The client picks its own participant id (a random UUID); '0-peer' sorts
  // below every such id, which decides the glare tie-break.
  self = participant('pending-self');
  remote = participant('0-peer');
  makeOffer = vi.fn(async (): Promise<RTCSessionDescriptionInit> => ({ type: 'offer', sdp: 'offer' }));
  const track = { enabled: true, stop: vi.fn() };
  vi.stubGlobal('window', { isSecureContext: true, setTimeout, clearTimeout });
  vi.stubGlobal('navigator', { mediaDevices: {
    getUserMedia: vi.fn(async () => ({ getAudioTracks: () => [track], getTracks: () => [track] })),
    enumerateDevices: vi.fn(async () => []),
  } });
  vi.stubGlobal('RTCPeerConnection', FakePeer);
  useVoiceStore.getState().reset();
  mocks.device.mockImplementation(() => self);
  mocks.socket.on.mockImplementation((event, handler) => { listeners.set(event, handler); });
  mocks.socket.off.mockImplementation((event) => { listeners.delete(event); });
  mocks.socket.emit.mockImplementation((event, body, ack) => {
    // The server takes the participant id the client chose.
    if (event === 'voice:join') self.participantId = body.participantId;
    ack?.(event === 'voice:join' ? { ok: true, self, participants: [remote], iceServers: [] } : { ok: true });
  });
  mocks.directory.mockImplementation(async () => [{ ...remote, identityKey: 'test-public-key' }]);
  mocks.sign.mockResolvedValue(signature);
  mocks.verify.mockResolvedValue(true);
});
afterEach(() => { useVoiceStore.getState().reset(); vi.unstubAllGlobals(); });

function receive(type: 'offer' | 'answer', sequence: number) {
  listeners.get('voice:signal')!({ signature, envelope: buildVoiceDescriptionEnvelope({
    channelId, signalId: crypto.randomUUID(), sequence,
    senderParticipantId: remote.participantId, senderDeviceId: remote.deviceId,
    targetParticipantId: self.participantId, description: { type, sdp: 'remote-description' },
  }) });
}

it('serializes a colliding offer and refreshes a directory missing the new peer', async () => {
  let finishOffer!: (value: RTCSessionDescriptionInit) => void;
  makeOffer = vi.fn(() => new Promise<RTCSessionDescriptionInit>((resolve) => { finishOffer = resolve; }));
  mocks.directory.mockResolvedValueOnce([]);
  const joining = useVoiceStore.getState().join(channelId);
  await vi.waitFor(() => expect(makeOffer).toHaveBeenCalledOnce());
  const peer = createdPeers[0];
  receive('offer', 1);
  expect(mocks.verify).not.toHaveBeenCalled();
  finishOffer({ type: 'offer', sdp: 'offer' });
  await joining;
  await vi.waitFor(() => expect(peer.changes).toContain('local:answer'));
  expect(peer.changes).toEqual(['local:offer', 'local:rollback', 'remote:offer', 'local:answer']);
  expect(mocks.directory).toHaveBeenCalledTimes(2);
  expect(useVoiceStore.getState().status).toBe('connected');
});

it('keeps the opposite side of glare on its offer until the peer answers', async () => {
  // 'z-peer' sorts above every UUID.
  remote.participantId = 'z-peer';
  await useVoiceStore.getState().join(channelId);
  const peer = createdPeers[0];
  receive('offer', 1);
  receive('answer', 2);
  await vi.waitFor(() => expect(peer.changes).toContain('remote:answer'));
  expect(peer.changes).toEqual(['local:offer', 'remote:answer']);
  expect(peer.signalingState).toBe('stable');
});

it('joins a server from before chosen participant ids for a direct call', async () => {
  const joins: unknown[] = [];
  mocks.socket.emit.mockImplementation((event, body, ack) => {
    if (event !== 'voice:join') return ack?.({ ok: true });
    joins.push(body);
    // An older server refuses the unknown field, then assigns an id itself.
    if (body.participantId) return ack?.({ ok: false, error: 'INVALID_REQUEST' });
    self.participantId = 'server-assigned';
    return ack?.({ ok: true, self, participants: [remote], iceServers: [] });
  });
  await useVoiceStore.getState().join(channelId);
  expect(joins).toHaveLength(2);
  expect(useVoiceStore.getState().status).toBe('connected');
  expect(useVoiceStore.getState().self?.participantId).toBe('server-assigned');
});

it('refuses a call through the media server under an id it did not choose', async () => {
  mocks.socket.emit.mockImplementation((event, body, ack) => {
    if (event !== 'voice:join') return ack?.({ ok: true });
    if (body.participantId) return ack?.({ ok: false, error: 'INVALID_REQUEST' });
    self.participantId = 'server-assigned';
    return ack?.({ ok: true, self, participants: [remote], iceServers: [], media: 'sfu' });
  });
  await useVoiceStore.getState().join(channelId);
  expect(useVoiceStore.getState().status).toBe('error');
  expect(mocks.socket.emit).toHaveBeenCalledWith('voice:leave', { channelId });
});

it('does not join a call through the media server from a browser that cannot encrypt its audio', async () => {
  mocks.socket.emit.mockImplementation((event, body, ack) => {
    if (event === 'voice:join') self.participantId = body.participantId;
    ack?.(event === 'voice:join' ? { ok: true, self, participants: [remote], iceServers: [], media: 'sfu' } : { ok: true });
  });
  expect(typeof (globalThis as { RTCRtpScriptTransform?: unknown }).RTCRtpScriptTransform).toBe('undefined');
  await useVoiceStore.getState().join(channelId);
  expect(useVoiceStore.getState().status).toBe('error');
  expect(useVoiceStore.getState().error).toBe('このブラウザーでは通話を安全に行えないため、参加できません。ブラウザーかアプリを最新にしてお試しください');
  expect(mocks.socket.emit).toHaveBeenCalledWith('voice:leave', { channelId });
  expect(createdPeers).toHaveLength(0);
});
