export const MESSAGE_CRYPTO_VERSION = 3;
/** Forum-channel events: v3 plus the authenticated post the event belongs to. */
export const FORUM_MESSAGE_CRYPTO_VERSION = 4;
/**
 * Every channel type: the event refMessageId names, and in a forum the first
 * message of the post, are named as their authors signed them (see
 * SignedMessageEnvelope.refBinding). The only layout accepted for an event
 * that names another message (referencesOtherMessages); an event without
 * references may keep v3/v4.
 */
export const BOUND_MESSAGE_CRYPTO_VERSION = 5;
/**
 * Every event a current client signs: v5 plus where the event stands in the
 * channel as its author's device saw it. Each device numbers its events in a
 * channel 1, 2, 3, … (deviceSeq), names the newest events of other devices
 * it had received (seenHeads), and an edit names the version it replaces
 * (supersedes). A server can still withhold or reorder events, but a client
 * can then tell (see SignedMessageEnvelope.deviceSeq). The only layout the
 * server accepts for new events.
 */
export const SEQUENCED_MESSAGE_CRYPTO_VERSION = 6;
const LEGACY_MESSAGE_CRYPTO_VERSION = 2;
/** The most events of other devices one v6 event can name as received (seenHeads). */
export const MAX_SEEN_HEADS = 8;
/** deviceSeq stays within a PostgreSQL integer. */
export const MAX_DEVICE_SEQUENCE = 2_147_483_647;

/** Attachments are bound to their message's signed idempotency key (the unbound v2 layout is refused). */
export const ATTACHMENT_CRYPTO_VERSION = 3;
export const ATTACHMENT_PLAINTEXT_CHUNK_BYTES = 5 * 1024 * 1024;
export const ATTACHMENT_GCM_TAG_BYTES = 16;
export const ATTACHMENT_NONCE_PREFIX_BYTES = 8;
export const VOICE_SIGNAL_PROTOCOL_VERSION = 1;
export const MAX_VOICE_PARTICIPANTS = 8;
export const VOICE_KEY_PROTOCOL_VERSION = 1;
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
  /**
   * Present exactly in v6 envelopes: this event's number among the events
   * its device wrote in the channel, from 1 with no gaps. The server refuses
   * a number the device already used, so a client that holds a device's
   * events n and n + 2 knows that n + 1 was not delivered, and one that
   * holds them in another order knows they were reordered.
   */
  deviceSeq?: number;
  /**
   * v6: the newest event of other devices this device had received when it
   * wrote the event, at most MAX_SEEN_HEADS devices, none its own. The event
   * comes after each of them; a client holding the event but not one of
   * them, or holding them in another order, can tell.
   */
  seenHeads?: SignedEventHead[];
  /**
   * v6: for an edit, the signed idempotency key of the version it replaces
   * (the message itself or its previous edit); null for every other event.
   * Only one edit can replace a version, so an older edit cannot be served
   * as the latest one.
   */
  supersedes?: string | null;
  type: 'message' | 'edit' | 'delete';
}

/**
 * One device's event in a channel, as v6 names it: the device, its number
 * and the idempotency key its author signed. An honest device never gives
 * two events the same number, so two different keys under one number mean
 * that the server showed different events to different members.
 */
export interface SignedEventHead {
  deviceId: string;
  deviceSeq: number;
  idempotencyKey: string;
}

/** Whether an envelope uses the v5 layout or later (references bound to what their authors signed). */
export function isBoundMessageEnvelope(envelope: Pick<SignedMessageEnvelope, 'refBinding'>): boolean {
  return envelope.refBinding !== undefined;
}

/** Whether an envelope uses the v6 layout (numbered per device). */
export function isSequencedMessageEnvelope(envelope: Pick<SignedMessageEnvelope, 'deviceSeq'>): boolean {
  return envelope.deviceSeq !== undefined;
}

/** Whether a number can be a deviceSeq. */
export function isDeviceSequence(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= MAX_DEVICE_SEQUENCE;
}

/**
 * Whether seenHeads is well formed for an event of this device: at most
 * MAX_SEEN_HEADS entries, one per device, none of them the event's own.
 */
export function isValidSeenHeads(heads: unknown, ownDeviceId: string): heads is SignedEventHead[] {
  if (!Array.isArray(heads) || heads.length > MAX_SEEN_HEADS) return false;
  const devices = new Set<string>();
  for (const head of heads) {
    if (!head || typeof head !== 'object') return false;
    const { deviceId, deviceSeq, idempotencyKey } = head as Record<string, unknown>;
    if (typeof deviceId !== 'string' || deviceId.length === 0 || deviceId === ownDeviceId || devices.has(deviceId)) return false;
    if (!isDeviceSequence(deviceSeq) || typeof idempotencyKey !== 'string' || idempotencyKey.length === 0) return false;
    devices.add(deviceId);
  }
  return true;
}

/**
 * Whether an event names another message: an edit or a deletion, a quote, or
 * in a forum any event after the post's first message. Such an event counts
 * only in v5, which also signs what it names; the older layouts name their
 * targets by server id only, which a server can serve another message under.
 */
export function referencesOtherMessages(envelope: Pick<SignedMessageEnvelope, 'refMessageId' | 'postId'>): boolean {
  return Boolean(envelope.refMessageId) || typeof envelope.postId === 'string';
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

/**
 * The signed context of a v6 envelope: everything but the ciphertext. Every
 * v6 event carries its bindings (null when it names nothing), its number, the
 * heads it saw and, for an edit, the version it replaces.
 */
function sequencedEnvelopeContext(envelope: Pick<
  SignedMessageEnvelope,
  'type' | 'channelId' | 'authorId' | 'deviceId' | 'keyVersion' | 'idempotencyKey' | 'refMessageId' | 'broadcastMention'
  | 'postId' | 'refBinding' | 'postBinding' | 'deviceSeq' | 'seenHeads' | 'supersedes'
>): unknown[] {
  if (typeof envelope.broadcastMention !== 'boolean') throw new Error('INVALID_SEQUENCED_ENVELOPE');
  if (envelope.refBinding === undefined) throw new Error('INVALID_SEQUENCED_ENVELOPE');
  const forum = envelope.postId !== undefined;
  if (forum) {
    assertForumEnvelope(envelope);
    if (envelope.postBinding === undefined) throw new Error('INVALID_SEQUENCED_ENVELOPE');
  } else if (envelope.postBinding !== undefined && envelope.postBinding !== null) throw new Error('INVALID_SEQUENCED_ENVELOPE');
  if (!isDeviceSequence(envelope.deviceSeq) || !isValidSeenHeads(envelope.seenHeads, envelope.deviceId)) {
    throw new Error('INVALID_SEQUENCED_ENVELOPE');
  }
  if (envelope.type === 'edit'
    ? typeof envelope.supersedes !== 'string' || envelope.supersedes.length === 0
    : envelope.supersedes !== null) throw new Error('INVALID_SEQUENCED_ENVELOPE');
  return [
    SEQUENCED_MESSAGE_CRYPTO_VERSION,
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
    envelope.deviceSeq,
    envelope.seenHeads!.map((head) => [head.deviceId, head.deviceSeq, head.idempotencyKey]),
    envelope.supersedes,
  ];
}

/** A deterministic, protocol-versioned byte representation for message signatures. */
export function serializeMessageEnvelope(envelope: SignedMessageEnvelope): string {
  if (isSequencedMessageEnvelope(envelope)) {
    return JSON.stringify([...sequencedEnvelopeContext(envelope), envelope.contentNonce, envelope.encryptedContent]);
  }
  if (envelope.seenHeads !== undefined || envelope.supersedes !== undefined) throw new Error('INVALID_SEQUENCED_ENVELOPE');
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
  | 'refBinding' | 'postBinding' | 'deviceSeq' | 'seenHeads' | 'supersedes'
>): string {
  if (isSequencedMessageEnvelope(envelope)) return JSON.stringify(sequencedEnvelopeContext(envelope));
  if (envelope.seenHeads !== undefined || envelope.supersedes !== undefined) throw new Error('INVALID_SEQUENCED_ENVELOPE');
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
   * a file cannot be moved to a different message.
   */
  messageIdempotencyKey: string;
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
  if (typeof envelope.messageIdempotencyKey !== 'string' || envelope.messageIdempotencyKey.length === 0) {
    throw new Error('INVALID_ATTACHMENT_ENVELOPE');
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

/**
 * One sender's frame key for an SFU call, sent to one other participant. The
 * key is encrypted to the recipient device (RSA-OAEP-256 with the encryption
 * key of its directory bundle) and the envelope is signed by the sender
 * device, so the server relays it without reading or changing it. Frames
 * under the key carry `keyId` as their SFrame key id.
 */
export interface SignedVoiceKeyEnvelope {
  type: 'voice-key';
  /** Strictly increasing for one sender and target participant. */
  sequence: number;
  channelId: string;
  senderParticipantId: string;
  senderDeviceId: string;
  /** Chosen at random by the target when it joined, so a key sent to an earlier call is refused. */
  targetParticipantId: string;
  targetDeviceId: string;
  keyId: number;
  wrappedKey: string;
}

/** Stable representation used by the browser device P-256 signature. */
export function serializeVoiceKeyEnvelope(envelope: SignedVoiceKeyEnvelope): string {
  return JSON.stringify([
    VOICE_KEY_PROTOCOL_VERSION,
    envelope.type,
    envelope.sequence,
    envelope.channelId,
    envelope.senderParticipantId,
    envelope.senderDeviceId,
    envelope.targetParticipantId,
    envelope.targetDeviceId,
    envelope.keyId,
    envelope.wrappedKey,
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
