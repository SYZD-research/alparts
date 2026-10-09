import type { SignedVoiceKeyEnvelope } from '@alparts/shared';
import { isExactObject } from './voice-signal-model';

/**
 * Shapes of what the server sends for calls through the media server. Media
 * parameters are checked again by mediasoup-client; here every answer must
 * have exactly the expected fields.
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PARTICIPANT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MEDIA_ID = /^[0-9a-f-]{1,64}$/;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const WRAPPED_KEY = /^[A-Za-z0-9+/]{342,1368}={0,2}$/;
const MAX_MEDIA_PARAMETERS_BYTES = 64 * 1024;

export interface SfuProducer {
  participantId: string;
  producerId: string;
}

export interface SfuJoin {
  rtpCapabilities: Record<string, unknown>;
  producers: SfuProducer[];
}

export interface SfuTransport {
  id: string;
  iceParameters: Record<string, unknown>;
  iceCandidates: Array<Record<string, unknown>>;
  dtlsParameters: Record<string, unknown>;
}

export interface SfuConsumer {
  id: string;
  producerId: string;
  kind: 'audio';
  rtpParameters: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isBoundedParameters(value: unknown): value is Record<string, unknown> {
  if (!isPlainObject(value)) return false;
  try {
    return JSON.stringify(value).length <= MAX_MEDIA_PARAMETERS_BYTES;
  } catch {
    return false;
  }
}

function parseProducer(value: unknown): SfuProducer | null {
  if (!isExactObject(value, ['participantId', 'producerId'])) return null;
  return typeof value.participantId === 'string' && PARTICIPANT_ID.test(value.participantId)
    && typeof value.producerId === 'string' && MEDIA_ID.test(value.producerId)
    ? { participantId: value.participantId, producerId: value.producerId }
    : null;
}

/** The answer to voice:sfu:join for this participant. */
export function parseSfuJoin(value: unknown, participantId: string, maxProducers: number): SfuJoin | null {
  if (!isExactObject(value, ['ok', 'participantId', 'rtpCapabilities', 'producers'])) return null;
  if (value.ok !== true || value.participantId !== participantId || !isBoundedParameters(value.rtpCapabilities)) return null;
  if (!Array.isArray(value.producers) || value.producers.length > maxProducers) return null;
  const producers = value.producers.map(parseProducer);
  if (producers.some((producer) => !producer || producer.participantId === participantId)) return null;
  if (new Set(producers.map((producer) => producer!.participantId)).size !== producers.length) return null;
  return { rtpCapabilities: value.rtpCapabilities, producers: producers as SfuProducer[] };
}

export function parseSfuTransport(value: unknown): SfuTransport | null {
  if (!isExactObject(value, ['ok', 'transport']) || value.ok !== true) return null;
  const transport = value.transport;
  if (!isExactObject(transport, ['id', 'iceParameters', 'iceCandidates', 'dtlsParameters'])) return null;
  if (
    typeof transport.id !== 'string' || !MEDIA_ID.test(transport.id)
    || !isBoundedParameters(transport.iceParameters)
    || !Array.isArray(transport.iceCandidates) || transport.iceCandidates.length > 16
    || !transport.iceCandidates.every(isBoundedParameters)
    || !isBoundedParameters(transport.dtlsParameters)
  ) return null;
  return transport as unknown as SfuTransport;
}

export function parseSfuProduced(value: unknown): string | null {
  return isExactObject(value, ['ok', 'producerId']) && value.ok === true
    && typeof value.producerId === 'string' && MEDIA_ID.test(value.producerId)
    ? value.producerId
    : null;
}

export function parseSfuConsumer(value: unknown, producerId: string): SfuConsumer | null {
  if (!isExactObject(value, ['ok', 'consumer']) || value.ok !== true) return null;
  const consumer = value.consumer;
  if (!isExactObject(consumer, ['id', 'producerId', 'kind', 'rtpParameters'])) return null;
  if (
    typeof consumer.id !== 'string' || !MEDIA_ID.test(consumer.id)
    || consumer.producerId !== producerId
    || consumer.kind !== 'audio'
    || !isBoundedParameters(consumer.rtpParameters)
  ) return null;
  return consumer as unknown as SfuConsumer;
}

export function isSfuOk(value: unknown): boolean {
  return isExactObject(value, ['ok']) && value.ok === true;
}

/** A stream someone in this call started sending. */
export function parseSfuProducerNotice(value: unknown, channelId: string): SfuProducer | null {
  if (!isExactObject(value, ['channelId', 'participantId', 'producerId']) || value.channelId !== channelId) return null;
  return parseProducer({ participantId: value.participantId, producerId: value.producerId });
}

/** A frame key relayed by the server (checked further by VoiceFrameKeys). */
export function parseVoiceKeyMessage(value: unknown): { envelope: SignedVoiceKeyEnvelope; signature: string } | null {
  if (!isExactObject(value, ['envelope', 'signature'])) return null;
  const { envelope, signature } = value;
  if (typeof signature !== 'string' || !SIGNATURE.test(signature)) return null;
  if (!isExactObject(envelope, [
    'type', 'sequence', 'channelId', 'senderParticipantId', 'senderDeviceId',
    'targetParticipantId', 'targetDeviceId', 'keyId', 'wrappedKey',
  ])) return null;
  if (
    envelope.type !== 'voice-key'
    || !Number.isSafeInteger(envelope.sequence) || (envelope.sequence as number) < 1
    || typeof envelope.channelId !== 'string' || !UUID.test(envelope.channelId)
    || typeof envelope.senderParticipantId !== 'string' || !PARTICIPANT_ID.test(envelope.senderParticipantId)
    || typeof envelope.senderDeviceId !== 'string' || !UUID.test(envelope.senderDeviceId)
    || typeof envelope.targetParticipantId !== 'string' || !PARTICIPANT_ID.test(envelope.targetParticipantId)
    || typeof envelope.targetDeviceId !== 'string' || !UUID.test(envelope.targetDeviceId)
    || !Number.isInteger(envelope.keyId) || (envelope.keyId as number) < 0 || (envelope.keyId as number) > 0xffff_ffff
    || typeof envelope.wrappedKey !== 'string' || !WRAPPED_KEY.test(envelope.wrappedKey)
  ) return null;
  return { envelope: envelope as unknown as SignedVoiceKeyEnvelope, signature };
}
