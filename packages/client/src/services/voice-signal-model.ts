import type {
  SignedVoiceSignalEnvelope,
  VoiceChannelPresence,
  VoiceIceServer,
  VoiceParticipant,
} from '@alparts/shared';
import { t } from '../i18n';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;

export interface IncomingVoiceSignal {
  envelope: SignedVoiceSignalEnvelope;
  signature: string;
}

export interface VoiceJoinResult {
  ok: boolean;
  error?: 'DEVICE_REQUIRED' | 'FORBIDDEN' | 'VOICE_CHANNEL_FULL' | 'INVALID_REQUEST';
  self?: VoiceParticipant;
  participants?: VoiceParticipant[];
  iceServers?: VoiceIceServer[];
}

export interface VoiceWatchResult {
  ok: boolean;
  channels: VoiceChannelPresence[];
}

export class VoiceSignalSequenceTracker {
  private readonly highestByParticipant = new Map<string, number>();

  constructor(private readonly participantLimit = 8) {
    if (!Number.isSafeInteger(participantLimit) || participantLimit < 1) {
      throw new Error('Invalid voice sequence-tracker limit');
    }
  }

  accept(participantId: string, sequence: number): boolean {
    if (!PARTICIPANT_ID.test(participantId) || !isSignalSequence(sequence)) return false;
    const previous = this.highestByParticipant.get(participantId);
    if (previous !== undefined && sequence <= previous) return false;
    if (previous === undefined && this.highestByParticipant.size >= this.participantLimit) return false;
    this.highestByParticipant.set(participantId, sequence);
    return true;
  }

  remove(participantId: string): void {
    this.highestByParticipant.delete(participantId);
  }

  clear(): void {
    this.highestByParticipant.clear();
  }
}

export function buildVoiceDescriptionEnvelope(input: {
  signalId: string;
  sequence: number;
  channelId: string;
  senderParticipantId: string;
  senderDeviceId: string;
  targetParticipantId: string;
  description: RTCSessionDescriptionInit;
}): SignedVoiceSignalEnvelope {
  if (
    !isSignalSequence(input.sequence)
    || (input.description.type !== 'offer' && input.description.type !== 'answer')
    || !input.description.sdp
  ) {
    throw new Error(t('音声通話SDPが不正です'));
  }
  return {
    type: 'voice-signal',
    signalId: input.signalId,
    sequence: input.sequence,
    channelId: input.channelId,
    senderParticipantId: input.senderParticipantId,
    senderDeviceId: input.senderDeviceId,
    targetParticipantId: input.targetParticipantId,
    kind: input.description.type,
    descriptionType: input.description.type,
    sdp: input.description.sdp,
    candidate: null,
    sdpMid: null,
    sdpMLineIndex: null,
    usernameFragment: null,
  };
}

export function buildVoiceIceEnvelope(input: {
  signalId: string;
  sequence: number;
  channelId: string;
  senderParticipantId: string;
  senderDeviceId: string;
  targetParticipantId: string;
  candidate: RTCIceCandidate;
}): SignedVoiceSignalEnvelope {
  if (!isSignalSequence(input.sequence)) throw new Error(t('音声通話sequenceが不正です'));
  const candidate = input.candidate.toJSON();
  if (!candidate.candidate) throw new Error(t('音声通話ICE candidateが不正です'));
  return {
    type: 'voice-signal',
    signalId: input.signalId,
    sequence: input.sequence,
    channelId: input.channelId,
    senderParticipantId: input.senderParticipantId,
    senderDeviceId: input.senderDeviceId,
    targetParticipantId: input.targetParticipantId,
    kind: 'ice',
    descriptionType: null,
    sdp: null,
    candidate: candidate.candidate,
    sdpMid: candidate.sdpMid ?? null,
    sdpMLineIndex: candidate.sdpMLineIndex ?? null,
    usernameFragment: candidate.usernameFragment ?? null,
  };
}

export function parseIncomingVoiceSignal(value: unknown): IncomingVoiceSignal | null {
  if (!isExactObject(value, ['envelope', 'signature'])) return null;
  if (typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) return null;
  const envelope = parseVoiceEnvelope(value.envelope);
  return envelope ? { envelope, signature: value.signature } : null;
}

export function parseVoiceParticipant(value: unknown): VoiceParticipant | null {
  if (!isExactObject(value, [
    'participantId', 'userId', 'deviceId', 'muted', 'speaking', 'joinedAt',
  ])) return null;
  if (
    typeof value.participantId !== 'string'
    || !PARTICIPANT_ID.test(value.participantId)
    || typeof value.userId !== 'string'
    || !UUID.test(value.userId)
    || typeof value.deviceId !== 'string'
    || !UUID.test(value.deviceId)
    || typeof value.muted !== 'boolean'
    || typeof value.speaking !== 'boolean'
    || (value.muted && value.speaking)
    || typeof value.joinedAt !== 'string'
    || value.joinedAt.length > 64
    || !Number.isFinite(Date.parse(value.joinedAt))
  ) return null;
  return value as unknown as VoiceParticipant;
}

export function parseVoiceJoinResult(value: unknown): VoiceJoinResult | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (candidate.ok === false) {
    if (!isExactObject(candidate, ['ok', 'error'])) return null;
    const error = candidate.error;
    if (!['DEVICE_REQUIRED', 'FORBIDDEN', 'VOICE_CHANNEL_FULL', 'INVALID_REQUEST'].includes(String(error))) return null;
    return { ok: false, error: error as VoiceJoinResult['error'] };
  }
  if (candidate.ok !== true) return null;
  if (!isExactObject(candidate, ['ok', 'self', 'participants', 'iceServers'])) return null;
  const self = parseVoiceParticipant(candidate.self);
  if (!self || !Array.isArray(candidate.participants) || candidate.participants.length > 8) return null;
  const participants = candidate.participants.map(parseVoiceParticipant);
  if (participants.some((participant) => !participant)) return null;
  const iceServers = normalizeVoiceIceServers(candidate.iceServers);
  if (!iceServers) return null;
  return { ok: true, self, participants: participants as VoiceParticipant[], iceServers };
}

export function parseVoiceChannelPresence(value: unknown): VoiceChannelPresence | null {
  if (!isExactObject(value, ['channelId', 'participants'])) return null;
  if (typeof value.channelId !== 'string' || !UUID.test(value.channelId)) return null;
  if (!Array.isArray(value.participants) || value.participants.length > 8) return null;
  const participants = value.participants.map(parseVoiceParticipant);
  if (participants.some((participant) => !participant)) return null;
  const participantIds = new Set((participants as VoiceParticipant[]).map((participant) => participant.participantId));
  if (participantIds.size !== participants.length) return null;
  return { channelId: value.channelId, participants: participants as VoiceParticipant[] };
}

export function parseVoiceWatchResult(value: unknown): VoiceWatchResult | null {
  if (!isExactObject(value, ['ok', 'channels']) || typeof value.ok !== 'boolean') return null;
  if (!Array.isArray(value.channels) || value.channels.length > 100) return null;
  const channels = value.channels.map(parseVoiceChannelPresence);
  if (channels.some((channel) => !channel)) return null;
  const channelIds = new Set((channels as VoiceChannelPresence[]).map((channel) => channel.channelId));
  if (channelIds.size !== channels.length) return null;
  return { ok: value.ok, channels: channels as VoiceChannelPresence[] };
}

export function normalizeVoiceIceServers(value: unknown): VoiceIceServer[] | null {
  if (!Array.isArray(value) || value.length > 4) return null;
  const result: VoiceIceServer[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
    const candidate = entry as Record<string, unknown>;
    if (Object.keys(candidate).some((key) => !['urls', 'username', 'credential'].includes(key))) return null;
    const urls = typeof candidate.urls === 'string' ? [candidate.urls] : candidate.urls;
    if (!Array.isArray(urls) || urls.length < 1 || urls.length > 4) return null;
    if (urls.some((url) => (
      typeof url !== 'string'
      || url.length > 512
      || /[\s\u0000-\u001f\u007f@]/.test(url)
      || !/^(?:stun|stuns|turn|turns):[^?#]+(?:\?transport=(?:udp|tcp))?$/i.test(url)
    ))) return null;
    const username = candidate.username;
    const credential = candidate.credential;
    if ((username === undefined) !== (credential === undefined)) return null;
    if (
      (username !== undefined && !isBoundedCredential(username))
      || (credential !== undefined && !isBoundedCredential(credential))
      || (urls.some((url) => /^turns?:/i.test(url as string)) && (!username || !credential))
    ) return null;
    result.push({
      urls: urls as string[],
      ...(username === undefined ? {} : { username: username as string, credential: credential as string }),
    });
  }
  return result;
}

function parseVoiceEnvelope(value: unknown): SignedVoiceSignalEnvelope | null {
  if (!isExactObject(value, [
    'type', 'signalId', 'sequence', 'channelId', 'senderParticipantId', 'senderDeviceId',
    'targetParticipantId', 'kind', 'descriptionType', 'sdp', 'candidate',
    'sdpMid', 'sdpMLineIndex', 'usernameFragment',
  ])) return null;
  if (
    value.type !== 'voice-signal'
    || typeof value.signalId !== 'string' || !UUID.test(value.signalId)
    || !isSignalSequence(value.sequence)
    || typeof value.channelId !== 'string' || !UUID.test(value.channelId)
    || typeof value.senderParticipantId !== 'string' || !PARTICIPANT_ID.test(value.senderParticipantId)
    || typeof value.senderDeviceId !== 'string' || !UUID.test(value.senderDeviceId)
    || typeof value.targetParticipantId !== 'string' || !PARTICIPANT_ID.test(value.targetParticipantId)
  ) return null;
  if (value.kind === 'offer' || value.kind === 'answer') {
    if (
      value.descriptionType !== value.kind
      || typeof value.sdp !== 'string' || value.sdp.length < 1 || value.sdp.length > 32 * 1024
      || value.candidate !== null || value.sdpMid !== null
      || value.sdpMLineIndex !== null || value.usernameFragment !== null
    ) return null;
  } else if (value.kind === 'ice') {
    if (
      value.descriptionType !== null || value.sdp !== null
      || typeof value.candidate !== 'string' || value.candidate.length < 1 || value.candidate.length > 2_048
      || !isNullableBoundedText(value.sdpMid)
      || !(value.sdpMLineIndex === null || (Number.isSafeInteger(value.sdpMLineIndex) && (value.sdpMLineIndex as number) >= 0 && (value.sdpMLineIndex as number) <= 65_535))
      || !isNullableBoundedText(value.usernameFragment)
    ) return null;
  } else return null;
  return value as unknown as SignedVoiceSignalEnvelope;
}

function isSignalSequence(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1;
}

function isExactObject(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value as Record<string, unknown>).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isNullableBoundedText(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && value.length <= 256);
}

function isBoundedCredential(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 256
    && !/[\u0000-\u001f\u007f]/.test(value);
}
