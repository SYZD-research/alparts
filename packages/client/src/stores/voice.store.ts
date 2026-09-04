import { create } from 'zustand';
import type { Socket } from 'socket.io-client';
import type {
  SignedVoiceSignalEnvelope,
  VoiceParticipant,
} from '@alparts/shared';
import { MAX_VOICE_PARTICIPANTS } from '@alparts/shared';
import { api } from '../services/api';
import {
  getActiveDevice,
  signVoiceSignalEnvelope,
  verifyVoiceSignalSignature,
} from '../services/crypto.service';
import { connectSocket } from '../services/socket';
import {
  VoiceSignalSequenceTracker,
  buildVoiceDescriptionEnvelope,
  buildVoiceIceEnvelope,
  parseIncomingVoiceSignal,
  parseVoiceJoinResult,
  parseVoiceParticipant,
} from '../services/voice-signal-model';

export type VoiceCallStatus = 'idle' | 'joining' | 'connected' | 'error';
export type VoiceCallMode = 'voice-activity' | 'push-to-talk';
export type VoiceConnectionQuality = 'connecting' | 'good' | 'fair' | 'poor';

export interface VoiceMediaDevice {
  deviceId: string;
  label: string;
}

interface VoiceState {
  status: VoiceCallStatus;
  channelId: string | null;
  self: VoiceParticipant | null;
  participants: VoiceParticipant[];
  participantsByChannel: Record<string, VoiceParticipant[]>;
  muted: boolean;
  speaking: boolean;
  mode: VoiceCallMode;
  pushToTalkActive: boolean;
  inputDevices: VoiceMediaDevice[];
  outputDevices: VoiceMediaDevice[];
  selectedInputId: string;
  selectedOutputId: string;
  quality: VoiceConnectionQuality;
  remoteStreamRevision: number;
  error: string | null;
  join: (channelId: string) => Promise<void>;
  leave: () => void;
  setMuted: (muted: boolean) => void;
  setMode: (mode: VoiceCallMode) => void;
  setPushToTalkActive: (active: boolean) => void;
  setInputDevice: (deviceId: string) => Promise<void>;
  setOutputDevice: (deviceId: string) => void;
  refreshDevices: () => Promise<void>;
  setChannelParticipants: (channelId: string, participants: VoiceParticipant[]) => void;
  replaceChannelParticipants: (channelIds: string[], entries: Array<{ channelId: string; participants: VoiceParticipant[] }>) => void;
  clearChannelParticipants: (channelId: string) => void;
  reset: () => void;
}

interface DeviceDirectoryEntry {
  deviceId: string;
  userId: string;
  identityKey: string;
}

interface VoiceSocketListeners {
  socket: Socket;
  signal: (value: unknown) => void;
  joined: (value: unknown) => void;
  updated: (value: unknown) => void;
  left: (value: unknown) => void;
  disconnected: () => void;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SIGNAL_ACK_TIMEOUT_MS = 10_000;

let callGeneration = 0;
let inputSwitchGeneration = 0;
let serverJoinedChannelId: string | null = null;
let localStream: MediaStream | null = null;
let runtimeIceServers: RTCIceServer[] = [];
let listeners: VoiceSocketListeners | null = null;
let directoryPromise: Promise<Map<string, DeviceDirectoryEntry>> | null = null;
let levelContext: AudioContext | null = null;
let levelSource: MediaStreamAudioSourceNode | null = null;
let levelAnalyser: AnalyserNode | null = null;
let levelTimer: ReturnType<typeof setInterval> | null = null;
let statsTimer: ReturnType<typeof setInterval> | null = null;
let statsRunning = false;
let lastSpeakingTransitionAt = 0;
let voiceCandidate = false;
let voiceCandidateSamples = 0;
let lastPublishedVoiceState = '';
const incomingSequences = new VoiceSignalSequenceTracker();
const MAX_PENDING_VOICE_OPERATIONS_PER_PEER = 64;
const outboundSequences = new Map<string, number>();
const outboundQueues = new Map<string, Promise<void>>();
const outboundQueueDepths = new Map<string, number>();
const peers = new Map<string, RTCPeerConnection>();
const peerQueues = new Map<string, Promise<void>>();
const peerQueueDepths = new Map<string, number>();
const pendingIce = new Map<string, RTCIceCandidateInit[]>();
const remoteStreams = new Map<string, MediaStream>();

const idleProjection = {
  status: 'idle' as const,
  channelId: null,
  self: null,
  participants: [] as VoiceParticipant[],
  muted: false,
  speaking: false,
  pushToTalkActive: false,
  quality: 'connecting' as const,
  error: null,
};

export const useVoiceStore = create<VoiceState>((set, get) => ({
  ...idleProjection,
  mode: 'voice-activity',
  inputDevices: [],
  outputDevices: [],
  selectedInputId: '',
  selectedOutputId: '',
  remoteStreamRevision: 0,
  participantsByChannel: {},

  join: async (channelId) => {
    if (
      get().channelId === channelId
      && (get().status === 'connected' || get().status === 'joining')
    ) return;
    teardownVoiceRuntime(true);
    const generation = ++callGeneration;
    set({
      ...idleProjection,
      status: 'joining',
      channelId,
      error: null,
    });

    try {
      assertVoiceBrowserSupport();
      const device = getActiveDevice();
      const stream = await acquireAudioStream(get().selectedInputId);
      if (generation !== callGeneration) {
        stopStream(stream);
        return;
      }
      localStream = stream;
      applyTransmissionState();

      const socket = connectSocket();
      await waitForSocketConnection(socket);
      if (generation !== callGeneration) return;
      attachVoiceListeners(socket, generation, channelId);

      // From this point a delayed acknowledgement may still mean the server
      // admitted us. Cleanup therefore sends a scoped leave even on timeout or
      // response-validation failure.
      serverJoinedChannelId = channelId;
      const rawJoin = await emitAcknowledged(socket, 'voice:join', { channelId });
      const joined = parseVoiceJoinResult(rawJoin);
      if (!joined) throw new Error('通話サーバーから不正な応答を受信しました');
      if (!joined.ok) throw new Error(joinErrorMessage(joined.error));
      if (!joined.self || !joined.participants || !joined.iceServers) {
        throw new Error('通話参加情報が不足しています');
      }
      if (
        generation !== callGeneration
        || joined.self.deviceId !== device.deviceId
        || joined.self.userId !== device.userId
      ) throw new Error('通話参加者の端末情報を検証できませんでした');

      const participantIds = new Set([joined.self.participantId]);
      for (const participant of joined.participants) {
        if (participantIds.has(participant.participantId)) {
          throw new Error('通話参加者一覧が重複しています');
        }
        participantIds.add(participant.participantId);
      }

      runtimeIceServers = joined.iceServers.map((server) => ({
        urls: [...server.urls],
        ...(server.username === undefined ? {} : {
          username: server.username,
          credential: server.credential,
        }),
      }));
      set({
        status: 'connected',
        channelId,
        self: joined.self,
        participants: [joined.self, ...joined.participants],
        participantsByChannel: {
          ...get().participantsByChannel,
          [channelId]: [joined.self, ...joined.participants],
        },
        muted: false,
        speaking: false,
        quality: joined.participants.length > 0 ? 'connecting' : 'good',
        error: null,
      });
      await get().refreshDevices();
      if (generation !== callGeneration) return;
      startLocalLevelMonitoring(generation);
      startConnectionStats(generation);

      // Only the newly joined participant creates offers. Existing peers wait
      // for them, avoiding offer glare without a second negotiation protocol.
      await Promise.allSettled(joined.participants.map(async (participant) => {
        const peer = createPeer(participant.participantId, generation);
        const offer = await peer.createOffer();
        await peer.setLocalDescription(offer);
        if (peer.localDescription) {
          await sendDescription(peer.localDescription, participant.participantId, generation);
        }
      }));
    } catch (error) {
      if (generation !== callGeneration) return;
      teardownVoiceRuntime(true);
      set({
        ...idleProjection,
        status: 'error',
        channelId,
        error: voiceErrorMessage(error),
      });
    }
  },

  leave: () => teardownVoiceRuntime(true),

  setMuted: (muted) => {
    if (get().status !== 'connected') return;
    set({ muted, speaking: muted ? false : get().speaking });
    applyTransmissionState();
    updateSelfProjection();
    publishLocalVoiceState();
  },

  setMode: (mode) => {
    set({ mode, pushToTalkActive: false, speaking: false });
    applyTransmissionState();
    updateSelfProjection();
    publishLocalVoiceState();
  },

  setPushToTalkActive: (active) => {
    if (get().mode !== 'push-to-talk' || get().status !== 'connected') return;
    set({ pushToTalkActive: active, speaking: active && !get().muted });
    applyTransmissionState();
    updateSelfProjection();
    publishLocalVoiceState();
  },

  setInputDevice: async (deviceId) => {
    set({ selectedInputId: deviceId, error: null });
    if (!localStream || get().status !== 'connected') return;
    const generation = callGeneration;
    const switchGeneration = ++inputSwitchGeneration;
    try {
      const replacement = await acquireAudioStream(deviceId);
      if (generation !== callGeneration || switchGeneration !== inputSwitchGeneration) {
        stopStream(replacement);
        return;
      }
      const replacementTrack = replacement.getAudioTracks()[0];
      if (!replacementTrack) {
        stopStream(replacement);
        throw new Error('選択したマイクから音声トラックを取得できませんでした');
      }
      const oldStream = localStream;
      const oldTrack = oldStream.getAudioTracks()[0] ?? null;
      replacementTrack.enabled = isTransmissionEnabled();
      const senders = [...peers.values()].flatMap((peer) => (
        peer.getSenders()
          .filter((sender) => sender.track?.kind === 'audio')
      ));
      const results = await Promise.allSettled(senders.map((sender) => sender.replaceTrack(replacementTrack)));
      if (generation !== callGeneration || switchGeneration !== inputSwitchGeneration) {
        stopStream(replacement);
        return;
      }
      if (results.some((result) => result.status === 'rejected')) {
        await Promise.allSettled(senders.map((sender, index) => (
          results[index].status === 'fulfilled' ? sender.replaceTrack(oldTrack) : Promise.resolve()
        )));
        stopStream(replacement);
        throw new Error('通話中のマイク切替を完了できませんでした');
      }
      localStream = replacement;
      applyTransmissionState();
      stopStream(oldStream);
      startLocalLevelMonitoring(generation);
      await get().refreshDevices();
    } catch (error) {
      if (generation === callGeneration && switchGeneration === inputSwitchGeneration) {
        set({ error: voiceErrorMessage(error) });
      }
    }
  },

  setOutputDevice: (deviceId) => set({ selectedOutputId: deviceId }),

  refreshDevices: async () => {
    if (!navigator.mediaDevices?.enumerateDevices) return;
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const inputDevices = devices
        .filter((device) => device.kind === 'audioinput')
        .map((device, index) => ({ deviceId: device.deviceId, label: device.label || `マイク ${index + 1}` }));
      const outputDevices = devices
        .filter((device) => device.kind === 'audiooutput')
        .map((device, index) => ({ deviceId: device.deviceId, label: device.label || `スピーカー ${index + 1}` }));
      set({ inputDevices, outputDevices });
    } catch {
      // Device enumeration is optional; the active default device still works.
    }
  },

  setChannelParticipants: (channelId, participants) => set((state) => ({
    participantsByChannel: { ...state.participantsByChannel, [channelId]: [...participants] },
  })),

  replaceChannelParticipants: (channelIds, entries) => set((state) => {
    const participantsByChannel = { ...state.participantsByChannel };
    for (const channelId of channelIds) delete participantsByChannel[channelId];
    for (const entry of entries) participantsByChannel[entry.channelId] = [...entry.participants];
    return { participantsByChannel };
  }),

  clearChannelParticipants: (channelId) => set((state) => {
    if (!Object.prototype.hasOwnProperty.call(state.participantsByChannel, channelId)) return state;
    const participantsByChannel = { ...state.participantsByChannel };
    delete participantsByChannel[channelId];
    return { participantsByChannel };
  }),

  reset: () => {
    teardownVoiceRuntime(true);
    set({
      ...idleProjection,
      mode: 'voice-activity',
      inputDevices: [],
      outputDevices: [],
      selectedInputId: '',
      selectedOutputId: '',
      participantsByChannel: {},
    });
  },
}));

/** Remote streams stay outside Zustand so browser MediaStream objects are not copied or persisted. */
export function getRemoteVoiceStream(participantId: string): MediaStream | null {
  return remoteStreams.get(participantId) ?? null;
}

function assertVoiceBrowserSupport(): void {
  if (!window.isSecureContext) throw new Error('音声通話にはHTTPSの安全な接続が必要です');
  if (!navigator.mediaDevices?.getUserMedia || typeof RTCPeerConnection === 'undefined') {
    throw new Error('このブラウザーは音声通話に対応していません');
  }
  if (typeof crypto.randomUUID !== 'function') throw new Error('安全な乱数APIを利用できません');
}

async function acquireAudioStream(deviceId: string): Promise<MediaStream> {
  const base: MediaTrackConstraints = {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
    channelCount: 1,
  };
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: deviceId ? { ...base, deviceId: { exact: deviceId } } : base,
      video: false,
    });
    if (stream.getAudioTracks().length < 1) {
      stopStream(stream);
      throw new Error('マイクの音声トラックを取得できませんでした');
    }
    return stream;
  } catch (error) {
    if (deviceId && isMissingMediaDevice(error)) {
      useVoiceStore.setState({ selectedInputId: '' });
      const fallback = await navigator.mediaDevices.getUserMedia({ audio: base, video: false });
      if (fallback.getAudioTracks().length < 1) {
        stopStream(fallback);
        throw new Error('マイクの音声トラックを取得できませんでした');
      }
      return fallback;
    }
    throw error;
  }
}

function isMissingMediaDevice(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'NotFoundError' || error.name === 'OverconstrainedError');
}

function attachVoiceListeners(socket: Socket, generation: number, channelId: string): void {
  detachVoiceListeners();
  const signal = (value: unknown) => {
    const parsed = parseIncomingVoiceSignal(value);
    if (!parsed || parsed.envelope.channelId !== channelId) return;
    const state = useVoiceStore.getState();
    const participant = state.participants.find((entry) => (
      entry.participantId === parsed.envelope.senderParticipantId
    ));
    if (
      state.status !== 'connected'
      || state.self?.participantId !== parsed.envelope.targetParticipantId
      || participant?.deviceId !== parsed.envelope.senderDeviceId
    ) return;
    enqueuePeerOperation(parsed.envelope.senderParticipantId, async () => {
      await processIncomingSignal(parsed.envelope, parsed.signature, generation);
    });
  };
  const joined = (value: unknown) => {
    if (generation !== callGeneration) return;
    const participant = parseVoiceParticipant(value);
    if (!participant) return;
    const state = useVoiceStore.getState();
    if (state.channelId !== channelId || state.status !== 'connected') return;
    const existing = state.participants.find((entry) => entry.participantId === participant.participantId);
    if (existing && (existing.userId !== participant.userId || existing.deviceId !== participant.deviceId)) return;
    if (!existing && state.participants.length >= MAX_VOICE_PARTICIPANTS) return;
    directoryPromise = null;
    const participants = existing
      ? state.participants.map((entry) => entry.participantId === participant.participantId ? participant : entry)
      : [...state.participants, participant];
    useVoiceStore.setState({
      participants,
      participantsByChannel: { ...state.participantsByChannel, [channelId]: participants },
      quality: 'connecting',
    });
  };
  const updated = (value: unknown) => {
    if (generation !== callGeneration) return;
    const participant = parseVoiceParticipant(value);
    if (!participant) return;
    const state = useVoiceStore.getState();
    const existing = state.participants.find((entry) => entry.participantId === participant.participantId);
    if (!existing || existing.userId !== participant.userId || existing.deviceId !== participant.deviceId) return;
    const participants = state.participants.map((entry) => entry.participantId === participant.participantId ? participant : entry);
    useVoiceStore.setState({
      participants,
      participantsByChannel: { ...state.participantsByChannel, [channelId]: participants },
    });
  };
  const left = (value: unknown) => {
    if (!isParticipantLeft(value, channelId) || generation !== callGeneration) return;
    removePeer(value.participantId);
    useVoiceStore.setState((state) => {
      const participants = state.participants.filter((entry) => entry.participantId !== value.participantId);
      return {
        participants,
        participantsByChannel: { ...state.participantsByChannel, [channelId]: participants },
        quality: state.participants.length <= 3 ? 'good' : state.quality,
      };
    });
  };
  const disconnected = () => {
    if (generation !== callGeneration) return;
    teardownVoiceRuntime(false);
    useVoiceStore.setState({
      ...idleProjection,
      status: 'error',
      channelId,
      participantsByChannel: {},
      error: '接続が切れたため、通話を終了しました',
    });
  };
  socket.on('voice:signal', signal);
  socket.on('voice:participant-joined', joined);
  socket.on('voice:participant-updated', updated);
  socket.on('voice:participant-left', left);
  socket.on('disconnect', disconnected);
  listeners = { socket, signal, joined, updated, left, disconnected };
  navigator.mediaDevices.addEventListener?.('devicechange', refreshMediaDevices);
}

function detachVoiceListeners(): void {
  if (listeners) {
    listeners.socket.off('voice:signal', listeners.signal);
    listeners.socket.off('voice:participant-joined', listeners.joined);
    listeners.socket.off('voice:participant-updated', listeners.updated);
    listeners.socket.off('voice:participant-left', listeners.left);
    listeners.socket.off('disconnect', listeners.disconnected);
    listeners = null;
  }
  navigator.mediaDevices?.removeEventListener?.('devicechange', refreshMediaDevices);
}

function refreshMediaDevices(): void {
  void useVoiceStore.getState().refreshDevices();
}

async function processIncomingSignal(
  envelope: SignedVoiceSignalEnvelope,
  signature: string,
  generation: number,
): Promise<void> {
  if (generation !== callGeneration) return;
  const state = useVoiceStore.getState();
  if (
    state.status !== 'connected'
    || state.channelId !== envelope.channelId
    || state.self?.participantId !== envelope.targetParticipantId
  ) return;
  const participant = state.participants.find((entry) => entry.participantId === envelope.senderParticipantId);
  if (!participant || participant.deviceId !== envelope.senderDeviceId) return;

  let directory: Map<string, DeviceDirectoryEntry>;
  try {
    directory = await loadDeviceDirectory(envelope.channelId);
  } catch {
    noteVoiceError('通話相手の接続情報を確認できませんでした');
    return;
  }
  if (generation !== callGeneration) return;
  const identity = directory.get(envelope.senderDeviceId);
  if (
    !identity
    || identity.userId !== participant.userId
    || !await verifyVoiceSignalSignature(envelope, signature, identity.identityKey)
    || !incomingSequences.accept(envelope.senderParticipantId, envelope.sequence)
  ) return;

  try {
    if (envelope.kind === 'offer') {
      const peer = createPeer(envelope.senderParticipantId, generation);
      if (peer.signalingState !== 'stable') return;
      await peer.setRemoteDescription({ type: 'offer', sdp: envelope.sdp! });
      await flushPendingIce(envelope.senderParticipantId, peer);
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      if (peer.localDescription) {
        await sendDescription(peer.localDescription, envelope.senderParticipantId, generation);
      }
      return;
    }
    if (envelope.kind === 'answer') {
      const peer = peers.get(envelope.senderParticipantId);
      if (!peer || peer.signalingState !== 'have-local-offer') return;
      await peer.setRemoteDescription({ type: 'answer', sdp: envelope.sdp! });
      await flushPendingIce(envelope.senderParticipantId, peer);
      return;
    }

    const candidate: RTCIceCandidateInit = {
      candidate: envelope.candidate!,
      sdpMid: envelope.sdpMid,
      sdpMLineIndex: envelope.sdpMLineIndex,
      usernameFragment: envelope.usernameFragment ?? undefined,
    };
    const peer = peers.get(envelope.senderParticipantId);
    if (!peer?.remoteDescription) {
      const queued = pendingIce.get(envelope.senderParticipantId) ?? [];
      if (queued.length < 256) queued.push(candidate);
      pendingIce.set(envelope.senderParticipantId, queued);
      return;
    }
    await peer.addIceCandidate(candidate);
  } catch {
    if (generation === callGeneration) useVoiceStore.setState({ quality: 'poor' });
  }
}

function createPeer(participantId: string, generation: number): RTCPeerConnection {
  const existing = peers.get(participantId);
  if (existing) return existing;
  if (!localStream) throw new Error('ローカル音声が初期化されていません');

  const peer = new RTCPeerConnection({ iceServers: runtimeIceServers });
  peers.set(participantId, peer);
  for (const track of localStream.getAudioTracks()) peer.addTrack(track, localStream);

  peer.onicecandidate = (event) => {
    if (!event.candidate || generation !== callGeneration) return;
    void sendIceCandidate(event.candidate, participantId, generation).catch(() => {
      if (generation === callGeneration) useVoiceStore.setState({ quality: 'fair' });
    });
  };
  peer.ontrack = (event) => {
    if (generation !== callGeneration) return;
    const stream = event.streams[0] ?? new MediaStream([event.track]);
    remoteStreams.set(participantId, stream);
    event.track.onended = () => {
      if (remoteStreams.get(participantId) === stream) {
        remoteStreams.delete(participantId);
        bumpRemoteStreamRevision();
      }
    };
    bumpRemoteStreamRevision();
  };
  const updateQuality = () => {
    if (generation !== callGeneration) return;
    if (peer.connectionState === 'failed' || peer.connectionState === 'disconnected') {
      useVoiceStore.setState({ quality: 'poor' });
    } else if (peer.connectionState === 'connected') {
      void measureConnectionQuality(generation);
    }
  };
  peer.onconnectionstatechange = updateQuality;
  peer.oniceconnectionstatechange = updateQuality;
  return peer;
}

async function sendDescription(
  description: RTCSessionDescription,
  targetParticipantId: string,
  generation: number,
): Promise<void> {
  const context = currentSignalContext(targetParticipantId, generation);
  if (!context) return;
  const envelope = buildVoiceDescriptionEnvelope({
    signalId: crypto.randomUUID(),
    sequence: nextOutboundSignalSequence(targetParticipantId),
    ...context,
    description,
  });
  await sendSignedSignal(envelope, generation);
}

async function sendIceCandidate(
  candidate: RTCIceCandidate,
  targetParticipantId: string,
  generation: number,
): Promise<void> {
  const context = currentSignalContext(targetParticipantId, generation);
  if (!context) return;
  const envelope = buildVoiceIceEnvelope({
    signalId: crypto.randomUUID(),
    sequence: nextOutboundSignalSequence(targetParticipantId),
    ...context,
    candidate,
  });
  await sendSignedSignal(envelope, generation);
}

function currentSignalContext(targetParticipantId: string, generation: number) {
  const state = useVoiceStore.getState();
  if (
    generation !== callGeneration
    || state.status !== 'connected'
    || !state.channelId
    || !state.self
    || !state.participants.some((participant) => participant.participantId === targetParticipantId)
  ) return null;
  return {
    channelId: state.channelId,
    senderParticipantId: state.self.participantId,
    senderDeviceId: state.self.deviceId,
    targetParticipantId,
  };
}

async function sendSignedSignal(envelope: SignedVoiceSignalEnvelope, generation: number): Promise<void> {
  const depth = outboundQueueDepths.get(envelope.targetParticipantId) ?? 0;
  if (depth >= MAX_PENDING_VOICE_OPERATIONS_PER_PEER) throw new Error('VOICE_SIGNAL_CAPACITY');
  outboundQueueDepths.set(envelope.targetParticipantId, depth + 1);
  const previous = outboundQueues.get(envelope.targetParticipantId) ?? Promise.resolve();
  const next = previous.catch(() => undefined).then(async () => {
    const signature = await signVoiceSignalEnvelope(envelope);
    if (generation !== callGeneration || !listeners?.socket.connected) return;
    const result = await emitAcknowledged(listeners.socket, 'voice:signal', { ...envelope, signature });
    if (!isSuccessfulAcknowledgement(result)) throw new Error('通話シグナリングを中継できませんでした');
  });
  outboundQueues.set(envelope.targetParticipantId, next);
  try {
    await next;
  } finally {
    decrementQueueDepth(outboundQueueDepths, envelope.targetParticipantId);
    if (outboundQueues.get(envelope.targetParticipantId) === next) {
      outboundQueues.delete(envelope.targetParticipantId);
    }
  }
}

function nextOutboundSignalSequence(targetParticipantId: string): number {
  const previous = outboundSequences.get(targetParticipantId) ?? 0;
  if (previous >= Number.MAX_SAFE_INTEGER) throw new Error('音声通話sequenceの上限に達しました');
  const next = previous + 1;
  outboundSequences.set(targetParticipantId, next);
  return next;
}

async function flushPendingIce(participantId: string, peer: RTCPeerConnection): Promise<void> {
  const candidates = pendingIce.get(participantId) ?? [];
  pendingIce.delete(participantId);
  for (const candidate of candidates) await peer.addIceCandidate(candidate);
}

function enqueuePeerOperation(participantId: string, operation: () => Promise<void>): void {
  const depth = peerQueueDepths.get(participantId) ?? 0;
  if (depth >= MAX_PENDING_VOICE_OPERATIONS_PER_PEER) {
    useVoiceStore.setState({ quality: 'fair' });
    return;
  }
  peerQueueDepths.set(participantId, depth + 1);
  const previous = peerQueues.get(participantId) ?? Promise.resolve();
  const next = previous.catch(() => undefined).then(operation);
  peerQueues.set(participantId, next);
  void next.finally(() => {
    decrementQueueDepth(peerQueueDepths, participantId);
    if (peerQueues.get(participantId) === next) peerQueues.delete(participantId);
  }).catch(() => undefined);
}

function decrementQueueDepth(depths: Map<string, number>, participantId: string): void {
  const remaining = (depths.get(participantId) ?? 1) - 1;
  if (remaining <= 0) depths.delete(participantId);
  else depths.set(participantId, remaining);
}

async function loadDeviceDirectory(channelId: string): Promise<Map<string, DeviceDirectoryEntry>> {
  if (!directoryPromise) {
    const requestedDeviceIds = [...new Set(useVoiceStore.getState().participants.map((entry) => entry.deviceId))];
    if (requestedDeviceIds.length < 1 || requestedDeviceIds.length > MAX_VOICE_PARTICIPANTS) {
      throw new Error('Invalid voice device directory request');
    }
    directoryPromise = api.getChannelDeviceDirectory(channelId, requestedDeviceIds).then((entries) => {
      if (entries.length > MAX_VOICE_PARTICIPANTS) throw new Error('Invalid device directory');
      const result = new Map<string, DeviceDirectoryEntry>();
      for (const entry of entries) {
        if (
          !UUID.test(entry.deviceId)
          || !UUID.test(entry.userId)
          || typeof entry.identityKey !== 'string'
          || entry.identityKey.length < 1
          || entry.identityKey.length > 16 * 1024
          || result.has(entry.deviceId)
        ) throw new Error('Invalid device directory');
        result.set(entry.deviceId, entry);
      }
      return result;
    }).catch((error) => {
      directoryPromise = null;
      throw error;
    });
  }
  return directoryPromise;
}

function startLocalLevelMonitoring(generation: number): void {
  stopLocalLevelMonitoring();
  if (!localStream) return;
  try {
    levelContext = new AudioContext();
    levelSource = levelContext.createMediaStreamSource(localStream);
    levelAnalyser = levelContext.createAnalyser();
    levelAnalyser.fftSize = 512;
    levelAnalyser.smoothingTimeConstant = 0.65;
    levelSource.connect(levelAnalyser);
    void levelContext.resume().catch(() => undefined);
    const samples = new Uint8Array(levelAnalyser.fftSize);
    levelTimer = setInterval(() => {
      if (generation !== callGeneration || !levelAnalyser) return;
      const state = useVoiceStore.getState();
      const transmitting = !state.muted && (state.mode === 'voice-activity' || state.pushToTalkActive);
      levelAnalyser.getByteTimeDomainData(samples);
      let sum = 0;
      for (const sample of samples) {
        const normalized = (sample - 128) / 128;
        sum += normalized * normalized;
      }
      const detected = transmitting && Math.sqrt(sum / samples.length) >= 0.035;
      if (detected === voiceCandidate) voiceCandidateSamples += 1;
      else {
        voiceCandidate = detected;
        voiceCandidateSamples = 1;
      }
      if (
        voiceCandidateSamples >= 3
        && detected !== state.speaking
        && Date.now() - lastSpeakingTransitionAt >= 750
      ) {
        lastSpeakingTransitionAt = Date.now();
        useVoiceStore.setState({ speaking: detected });
        updateSelfProjection();
        publishLocalVoiceState();
      }
    }, 120);
  } catch {
    // Audio still transmits if level metering is unavailable.
  }
}

function stopLocalLevelMonitoring(): void {
  if (levelTimer) clearInterval(levelTimer);
  levelTimer = null;
  levelSource?.disconnect();
  levelAnalyser?.disconnect();
  levelSource = null;
  levelAnalyser = null;
  if (levelContext) void levelContext.close().catch(() => undefined);
  levelContext = null;
  voiceCandidate = false;
  voiceCandidateSamples = 0;
}

function applyTransmissionState(): void {
  const enabled = isTransmissionEnabled();
  for (const track of localStream?.getAudioTracks() ?? []) track.enabled = enabled;
  const state = useVoiceStore.getState();
  if (!enabled && state.speaking) useVoiceStore.setState({ speaking: false });
}

function isTransmissionEnabled(): boolean {
  const state = useVoiceStore.getState();
  return !state.muted && (state.mode === 'voice-activity' || state.pushToTalkActive);
}

function updateSelfProjection(): void {
  const state = useVoiceStore.getState();
  if (!state.self) return;
  const self = { ...state.self, muted: state.muted, speaking: state.muted ? false : state.speaking };
  const participants = state.participants.map((participant) => (
    participant.participantId === self.participantId ? self : participant
  ));
  useVoiceStore.setState({
    self,
    participants,
    ...(state.channelId ? {
      participantsByChannel: { ...state.participantsByChannel, [state.channelId]: participants },
    } : {}),
  });
}

function publishLocalVoiceState(): void {
  const state = useVoiceStore.getState();
  if (state.status !== 'connected' || !state.channelId || !listeners?.socket.connected) return;
  const speaking = state.muted ? false : state.speaking;
  const serialized = `${state.muted}:${speaking}`;
  if (serialized === lastPublishedVoiceState) return;
  lastPublishedVoiceState = serialized;
  listeners.socket.emit('voice:state', { channelId: state.channelId, muted: state.muted, speaking });
}

function startConnectionStats(generation: number): void {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(() => void measureConnectionQuality(generation), 3_000);
}

async function measureConnectionQuality(generation: number): Promise<void> {
  if (statsRunning || generation !== callGeneration) return;
  statsRunning = true;
  try {
    if (peers.size === 0) {
      useVoiceStore.setState({ quality: 'good' });
      return;
    }
    let worst: VoiceConnectionQuality = 'good';
    for (const peer of peers.values()) {
      if (peer.connectionState === 'failed' || peer.connectionState === 'disconnected') {
        worst = 'poor';
        break;
      }
      if (peer.connectionState !== 'connected') worst = worseQuality(worst, 'connecting');
      const report = await peer.getStats();
      report.forEach((raw) => {
        const stat = raw as unknown as Record<string, unknown>;
        if (stat.type === 'inbound-rtp' && (stat.kind === 'audio' || stat.mediaType === 'audio')) {
          const received = numberStat(stat.packetsReceived);
          const lost = Math.max(0, numberStat(stat.packetsLost));
          const total = received + lost;
          const loss = total > 0 ? lost / total : 0;
          if (loss >= 0.08) worst = 'poor';
          else if (loss >= 0.03) worst = worseQuality(worst, 'fair');
        }
        if (stat.type === 'candidate-pair' && stat.state === 'succeeded') {
          const roundTrip = numberStat(stat.currentRoundTripTime);
          if (roundTrip >= 0.8) worst = 'poor';
          else if (roundTrip >= 0.35) worst = worseQuality(worst, 'fair');
        }
      });
    }
    if (generation === callGeneration) useVoiceStore.setState({ quality: worst });
  } catch {
    if (generation === callGeneration) useVoiceStore.setState({ quality: 'fair' });
  } finally {
    statsRunning = false;
  }
}

function worseQuality(left: VoiceConnectionQuality, right: VoiceConnectionQuality): VoiceConnectionQuality {
  const rank: Record<VoiceConnectionQuality, number> = { good: 0, connecting: 1, fair: 2, poor: 3 };
  return rank[left] >= rank[right] ? left : right;
}

function numberStat(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function removePeer(participantId: string): void {
  const peer = peers.get(participantId);
  if (peer) {
    peer.onicecandidate = null;
    peer.ontrack = null;
    peer.onconnectionstatechange = null;
    peer.oniceconnectionstatechange = null;
    peer.close();
  }
  peers.delete(participantId);
  peerQueues.delete(participantId);
  peerQueueDepths.delete(participantId);
  outboundQueues.delete(participantId);
  outboundQueueDepths.delete(participantId);
  outboundSequences.delete(participantId);
  incomingSequences.remove(participantId);
  pendingIce.delete(participantId);
  if (remoteStreams.delete(participantId)) bumpRemoteStreamRevision();
}

function bumpRemoteStreamRevision(): void {
  useVoiceStore.setState((state) => ({ remoteStreamRevision: state.remoteStreamRevision + 1 }));
}

function teardownVoiceRuntime(notifyServer: boolean): void {
  callGeneration += 1;
  inputSwitchGeneration += 1;
  const socket = listeners?.socket;
  const channelId = serverJoinedChannelId;
  const current = useVoiceStore.getState();
  detachVoiceListeners();
  if (notifyServer && channelId && socket?.connected) socket.emit('voice:leave', { channelId });
  serverJoinedChannelId = null;
  directoryPromise = null;
  runtimeIceServers = [];
  incomingSequences.clear();
  outboundSequences.clear();
  outboundQueues.clear();
  outboundQueueDepths.clear();
  lastPublishedVoiceState = '';
  lastSpeakingTransitionAt = 0;
  stopLocalLevelMonitoring();
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = null;
  statsRunning = false;
  for (const participantId of peers.keys()) removePeer(participantId);
  peerQueues.clear();
  peerQueueDepths.clear();
  pendingIce.clear();
  if (remoteStreams.size > 0) {
    remoteStreams.clear();
    bumpRemoteStreamRevision();
  }
  stopStream(localStream);
  localStream = null;
  const participantsByChannel = { ...current.participantsByChannel };
  if (current.channelId && current.self) {
    participantsByChannel[current.channelId] = (participantsByChannel[current.channelId] || current.participants)
      .filter((participant) => participant.participantId !== current.self?.participantId);
  }
  useVoiceStore.setState({ ...idleProjection, participantsByChannel });
}

function stopStream(stream: MediaStream | null): void {
  for (const track of stream?.getTracks() ?? []) track.stop();
}

function noteVoiceError(message: string): void {
  if (useVoiceStore.getState().status === 'connected') useVoiceStore.setState({ error: message });
}

function isParticipantLeft(
  value: unknown,
  channelId: string,
): value is { channelId: string; participantId: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return Object.keys(candidate).length === 2
    && candidate.channelId === channelId
    && typeof candidate.participantId === 'string'
    && PARTICIPANT_ID.test(candidate.participantId);
}

function isSuccessfulAcknowledgement(value: unknown): boolean {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && (value as Record<string, unknown>).ok === true);
}

async function emitAcknowledged(socket: Socket, event: string, payload: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error('通話サーバーの応答がタイムアウトしました'));
    }, SIGNAL_ACK_TIMEOUT_MS);
    socket.emit(event, payload, (result: unknown) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      resolve(result);
    });
  });
}

async function waitForSocketConnection(socket: Socket): Promise<void> {
  if (socket.connected) return;
  await new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => finish(new Error('リアルタイム接続がタイムアウトしました')), SIGNAL_ACK_TIMEOUT_MS);
    const onConnect = () => finish();
    const onError = () => finish(new Error('リアルタイム接続を確立できませんでした'));
    const finish = (error?: Error) => {
      window.clearTimeout(timer);
      socket.off('connect', onConnect);
      socket.off('connect_error', onError);
      if (error) reject(error);
      else resolve();
    };
    socket.on('connect', onConnect);
    socket.on('connect_error', onError);
    socket.connect();
  });
}

function joinErrorMessage(error: string | undefined): string {
  if (error === 'DEVICE_REQUIRED') return 'この端末を登録してから通話に参加してください';
  if (error === 'FORBIDDEN') return 'このチャンネルの通話に参加する権限がありません';
  if (error === 'VOICE_CHANNEL_FULL') return 'この通話は参加上限（8人）に達しています';
  return '通話に参加できませんでした';
}

function voiceErrorMessage(error: unknown): string {
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError' || error.name === 'SecurityError') return 'マイクの使用が許可されていません';
    if (error.name === 'NotFoundError') return '利用できるマイクが見つかりません';
    if (error.name === 'NotReadableError') return 'マイクをほかのアプリが使用しているため開始できません';
  }
  return '音声通話を開始できませんでした。もう一度お試しください';
}
