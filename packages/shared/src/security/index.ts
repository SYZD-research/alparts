export const MESSAGE_CRYPTO_VERSION = 3;
const LEGACY_MESSAGE_CRYPTO_VERSION = 2;

export const ATTACHMENT_CRYPTO_VERSION = 2;
export const ATTACHMENT_PLAINTEXT_CHUNK_BYTES = 5 * 1024 * 1024;
export const ATTACHMENT_GCM_TAG_BYTES = 16;
export const ATTACHMENT_NONCE_PREFIX_BYTES = 8;
export const VOICE_SIGNAL_PROTOCOL_VERSION = 1;
export const MAX_VOICE_PARTICIPANTS = 8;
export const ATTACHMENT_CHUNK_AAD_FORMAT =
  'alparts-attachment-chunk-v1\\0{uploadId}\\0{messageId}\\0{index}\\0{chunkCount}\\0{plaintextSize}';

export function serializeDeviceChallengeProof(userId: string, challenge: string): string {
  return JSON.stringify([1, 'device-session-proof', userId, challenge]);
}

export interface SignedChannelKeyWrap {
  channelId: string;
  keyVersion: number;
  keyCommitment: string;
  recipientDeviceId: string;
  encryptedKey: string;
}

export function serializeChannelKeyWrap(envelope: SignedChannelKeyWrap): string {
  return JSON.stringify([
    1,
    'channel-key-wrap',
    envelope.channelId,
    envelope.keyVersion,
    envelope.keyCommitment,
    envelope.recipientDeviceId,
    envelope.encryptedKey,
  ]);
}

export interface SignedChannelKeyAcknowledgement extends SignedChannelKeyWrap {
  deliveryId: string;
  distributorDeviceId: string;
}

/** Proof that the recipient device accepted one exact committed wrap. */
export function serializeChannelKeyAcknowledgement(envelope: SignedChannelKeyAcknowledgement): string {
  return JSON.stringify([
    2,
    'channel-key-delivery-acknowledgement',
    envelope.deliveryId,
    envelope.channelId,
    envelope.keyVersion,
    envelope.keyCommitment,
    envelope.recipientDeviceId,
    envelope.distributorDeviceId,
    envelope.encryptedKey,
  ]);
}

export interface SignedChannelKeyEpochAbort {
  channelId: string;
  keyVersion: number;
  keyCommitment: string;
  deviceId: string;
}

/** Proof that an active-key holder deliberately aborts one pending epoch. */
export function serializeChannelKeyEpochAbort(envelope: SignedChannelKeyEpochAbort): string {
  return JSON.stringify([
    1,
    'channel-key-epoch-abort',
    envelope.channelId,
    envelope.keyVersion,
    envelope.keyCommitment,
    envelope.deviceId,
  ]);
}

export interface SignedChannelKeyFreshStart {
  channelId: string;
  keyVersion: number;
  keyCommitment: string;
  deviceId: string;
}

/** Proof that one device explicitly chose to continue without prior history. */
export function serializeChannelKeyFreshStart(envelope: SignedChannelKeyFreshStart): string {
  return JSON.stringify([
    1,
    'channel-key-fresh-start',
    envelope.channelId,
    envelope.keyVersion,
    envelope.keyCommitment,
    envelope.deviceId,
  ]);
}

export interface SignedMessageEnvelope {
  channelId: string;
  authorId: string;
  deviceId: string;
  encryptedContent: string;
  contentNonce: string;
  keyVersion: number;
  idempotencyKey: string;
  refMessageId?: string | null;
  /** Null/undefined is reserved for legacy v2 rows. New envelopes carry true or false. */
  broadcastMention?: boolean | null;
  type: 'message' | 'edit' | 'delete';
}

/** A deterministic, protocol-versioned byte representation for message signatures. */
export function serializeMessageEnvelope(envelope: SignedMessageEnvelope): string {
  if (envelope.broadcastMention === null || envelope.broadcastMention === undefined) {
    return JSON.stringify([
      LEGACY_MESSAGE_CRYPTO_VERSION,
      envelope.type,
      envelope.channelId,
      envelope.authorId,
      envelope.deviceId,
      envelope.keyVersion,
      envelope.idempotencyKey,
      envelope.refMessageId ?? null,
      envelope.contentNonce,
      envelope.encryptedContent,
    ]);
  }
  return JSON.stringify([
    MESSAGE_CRYPTO_VERSION,
    envelope.type,
    envelope.channelId,
    envelope.authorId,
    envelope.deviceId,
    envelope.keyVersion,
    envelope.idempotencyKey,
    envelope.refMessageId ?? null,
    envelope.broadcastMention,
    envelope.contentNonce,
    envelope.encryptedContent,
  ]);
}

export function serializeMessageAad(envelope: Pick<
  SignedMessageEnvelope,
  'type' | 'channelId' | 'authorId' | 'deviceId' | 'keyVersion' | 'idempotencyKey' | 'refMessageId' | 'broadcastMention'
>): string {
  if (envelope.broadcastMention === null || envelope.broadcastMention === undefined) {
    return JSON.stringify([
      LEGACY_MESSAGE_CRYPTO_VERSION,
      envelope.type,
      envelope.channelId,
      envelope.authorId,
      envelope.deviceId,
      envelope.keyVersion,
      envelope.idempotencyKey,
      envelope.refMessageId ?? null,
    ]);
  }
  return JSON.stringify([
    MESSAGE_CRYPTO_VERSION,
    envelope.type,
    envelope.channelId,
    envelope.authorId,
    envelope.deviceId,
    envelope.keyVersion,
    envelope.idempotencyKey,
    envelope.refMessageId ?? null,
    envelope.broadcastMention,
  ]);
}

/**
 * Client-originated attachment metadata covered by the uploader device's
 * signature. The server-generated attachment id is intentionally absent: the
 * upload reservation id is the stable identifier known before finalization.
 */
export interface SignedAttachmentEnvelope {
  type: 'attachment';
  uploadId: string;
  messageId: string;
  channelId: string;
  authorId: string;
  deviceId: string;
  keyVersion: number;
  filenameEnc: string;
  mimeType: string;
  wrappedKey: string;
  noncePrefix: string;
  plaintextSize: number;
  chunkCount: number;
}

/** A deterministic, protocol-versioned representation for attachment signatures. */
export function serializeAttachmentEnvelope(envelope: SignedAttachmentEnvelope): string {
  return JSON.stringify([
    ATTACHMENT_CRYPTO_VERSION,
    envelope.type,
    envelope.uploadId,
    envelope.messageId,
    envelope.channelId,
    envelope.authorId,
    envelope.deviceId,
    envelope.keyVersion,
    envelope.filenameEnc,
    envelope.mimeType,
    envelope.wrappedKey,
    envelope.noncePrefix,
    envelope.plaintextSize,
    envelope.chunkCount,
  ]);
}

export function serializeAttachmentFilenameAad(messageId: string): string {
  return `alparts-attachment-filename-v1\0${messageId}`;
}

export function serializeAttachmentWrappedKeyAad(messageId: string, uploadId: string): string {
  return `alparts-attachment-file-key-v1\0${messageId}\0${uploadId}`;
}

export function serializeAttachmentChunkAad(
  uploadId: string,
  messageId: string,
  index: number,
  chunkCount: number,
  plaintextSize: number,
): string {
  return `alparts-attachment-chunk-v1\0${uploadId}\0${messageId}\0${index}\0${chunkCount}\0${plaintextSize}`;
}

export type VoiceSignalKind = 'offer' | 'answer' | 'ice';

/**
 * Exact browser-to-browser WebRTC signaling statement. Offer/answer SDP binds
 * the peer DTLS fingerprint to the authenticated application device. ICE is
 * signed as well so the signaling relay cannot silently rewrite routing data.
 */
export interface SignedVoiceSignalEnvelope {
  type: 'voice-signal';
  signalId: string;
  /** Strictly increasing for one sender/target participant pair. */
  sequence: number;
  channelId: string;
  senderParticipantId: string;
  senderDeviceId: string;
  targetParticipantId: string;
  kind: VoiceSignalKind;
  descriptionType: 'offer' | 'answer' | null;
  sdp: string | null;
  candidate: string | null;
  sdpMid: string | null;
  sdpMLineIndex: number | null;
  usernameFragment: string | null;
}

/** Stable representation used by the browser device P-256 signature. */
export function serializeVoiceSignalEnvelope(envelope: SignedVoiceSignalEnvelope): string {
  return JSON.stringify([
    VOICE_SIGNAL_PROTOCOL_VERSION,
    envelope.type,
    envelope.signalId,
    envelope.sequence,
    envelope.channelId,
    envelope.senderParticipantId,
    envelope.senderDeviceId,
    envelope.targetParticipantId,
    envelope.kind,
    envelope.descriptionType,
    envelope.sdp,
    envelope.candidate,
    envelope.sdpMid,
    envelope.sdpMLineIndex,
    envelope.usernameFragment,
  ]);
}

export interface VoiceParticipant {
  participantId: string;
  userId: string;
  deviceId: string;
  muted: boolean;
  speaking: boolean;
  joinedAt: string;
}

export interface VoiceChannelPresence {
  channelId: string;
  participants: VoiceParticipant[];
}

export interface VoiceIceServer {
  urls: string[];
  username?: string;
  credential?: string;
}
