export const MESSAGE_CRYPTO_VERSION = 3;
/** Forum-channel events: v3 plus the authenticated post the event belongs to. */
export const FORUM_MESSAGE_CRYPTO_VERSION = 4;
/**
 * Every channel type: the event refMessageId names, and in a forum the first
 * message of the post, are named as their authors signed them (see
 * SignedMessageEnvelope.refBinding).
 */
export const BOUND_MESSAGE_CRYPTO_VERSION = 5;
const LEGACY_MESSAGE_CRYPTO_VERSION = 2;

export const ATTACHMENT_CRYPTO_VERSION = 3;
/** Attachments signed before they were bound to their message's idempotency key. */
const LEGACY_ATTACHMENT_CRYPTO_VERSION = 2;
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

/**
 * An event as its author signed it. Within a channel the server keeps one
 * event per author and idempotency key, and it cannot sign for an author, so
 * it cannot make another event carry this pair.
 */
export interface SignedEventReference {
  authorId: string;
  idempotencyKey: string;
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
  /**
   * Present (string or null) exactly for events in forum channels. Null marks
   * the event that starts a post; every other forum event names its post.
   * Undefined keeps the v2/v3 layout used by every other channel type.
   */
  postId?: string | null;
  /**
   * Present (an object or null) exactly in v5 envelopes: the event that
   * refMessageId names, as its author signed it; null when there is none.
   * Server ids are not signed by the events they name, so without this a
   * server could serve another message of the same author under the id and
   * move an edit, a deletion or a quote to it.
   */
  refBinding?: SignedEventReference | null;
  /** v5 forum events: the first message of the post postId names; null for that message itself. */
  postBinding?: SignedEventReference | null;
  type: 'message' | 'edit' | 'delete';
}

/** Whether an envelope uses the v5 layout (references bound to what their authors signed). */
export function isBoundMessageEnvelope(envelope: Pick<SignedMessageEnvelope, 'refBinding'>): boolean {
  return envelope.refBinding !== undefined;
}

function boundReference(id: string | null | undefined, binding: SignedEventReference | null | undefined) {
  if (id === null || id === undefined) {
    if (binding !== null && binding !== undefined) throw new Error('INVALID_BOUND_ENVELOPE');
    return null;
  }
  if (
    !binding
    || typeof binding.authorId !== 'string' || binding.authorId.length === 0
    || typeof binding.idempotencyKey !== 'string' || binding.idempotencyKey.length === 0
  ) throw new Error('INVALID_BOUND_ENVELOPE');
  return [id, binding.authorId, binding.idempotencyKey];
}

/** The signed context of a v5 envelope: everything but the ciphertext. */
function boundEnvelopeContext(envelope: Pick<
  SignedMessageEnvelope,
  'type' | 'channelId' | 'authorId' | 'deviceId' | 'keyVersion' | 'idempotencyKey' | 'refMessageId' | 'broadcastMention'
  | 'postId' | 'refBinding' | 'postBinding'
>): unknown[] {
  if (typeof envelope.broadcastMention !== 'boolean') throw new Error('INVALID_BOUND_ENVELOPE');
  const forum = envelope.postId !== undefined;
  if (forum) assertForumEnvelope(envelope);
  else if (envelope.postBinding !== undefined && envelope.postBinding !== null) throw new Error('INVALID_BOUND_ENVELOPE');
  return [
    BOUND_MESSAGE_CRYPTO_VERSION,
    forum ? 'forum' : 'text',
    envelope.type,
    envelope.channelId,
    envelope.authorId,
    envelope.deviceId,
    envelope.keyVersion,
    envelope.idempotencyKey,
    boundReference(envelope.refMessageId, envelope.refBinding),
    forum ? boundReference(envelope.postId, envelope.postBinding) : null,
    envelope.broadcastMention,
  ];
}

/** A deterministic, protocol-versioned byte representation for message signatures. */
export function serializeMessageEnvelope(envelope: SignedMessageEnvelope): string {
  if (isBoundMessageEnvelope(envelope)) {
    return JSON.stringify([...boundEnvelopeContext(envelope), envelope.contentNonce, envelope.encryptedContent]);
  }
  if (envelope.postId !== undefined) {
    assertForumEnvelope(envelope);
    return JSON.stringify([
      FORUM_MESSAGE_CRYPTO_VERSION,
      envelope.type,
      envelope.channelId,
      envelope.authorId,
      envelope.deviceId,
      envelope.keyVersion,
      envelope.idempotencyKey,
      envelope.refMessageId ?? null,
      envelope.postId,
      envelope.broadcastMention,
      envelope.contentNonce,
      envelope.encryptedContent,
    ]);
  }
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
  'type' | 'channelId' | 'authorId' | 'deviceId' | 'keyVersion' | 'idempotencyKey' | 'refMessageId' | 'broadcastMention' | 'postId'
  | 'refBinding' | 'postBinding'
>): string {
  if (isBoundMessageEnvelope(envelope)) return JSON.stringify(boundEnvelopeContext(envelope));
  if (envelope.postId !== undefined) {
    assertForumEnvelope(envelope);
    return JSON.stringify([
      FORUM_MESSAGE_CRYPTO_VERSION,
      envelope.type,
      envelope.channelId,
      envelope.authorId,
      envelope.deviceId,
      envelope.keyVersion,
      envelope.idempotencyKey,
      envelope.refMessageId ?? null,
      envelope.postId,
      envelope.broadcastMention,
    ]);
  }
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
 * A forum envelope has no legacy form: the mention flag is always explicit,
 * and only the message that starts a post may omit its post.
 */
function assertForumEnvelope(envelope: Pick<SignedMessageEnvelope, 'type' | 'broadcastMention' | 'postId'>): void {
  if (typeof envelope.broadcastMention !== 'boolean') throw new Error('INVALID_FORUM_ENVELOPE');
  if (envelope.postId === null ? envelope.type !== 'message' : typeof envelope.postId !== 'string') {
    throw new Error('INVALID_FORUM_ENVELOPE');
  }
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
  /**
   * The idempotency key signed into the message the file belongs to. The
   * server assigns message ids, but cannot give another message this key, so
   * a file cannot be moved to a different message. Absent only in legacy v2
   * signatures.
   */
  messageIdempotencyKey?: string;
}

/** A deterministic, protocol-versioned representation for attachment signatures. */
export function serializeAttachmentEnvelope(envelope: SignedAttachmentEnvelope): string {
  const fields = [
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
  ];
  if (envelope.messageIdempotencyKey === undefined) {
    return JSON.stringify([LEGACY_ATTACHMENT_CRYPTO_VERSION, ...fields]);
  }
  return JSON.stringify([ATTACHMENT_CRYPTO_VERSION, ...fields, envelope.messageIdempotencyKey]);
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
