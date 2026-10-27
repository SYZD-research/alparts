import { isDeviceSequence, isValidSeenHeads, type SignedEventHead, type SignedMessageEnvelope } from '@alparts/shared';

/** The exact request body for sending a signed message. */
export interface SealedMessageRequest {
  encryptedContent: string;
  contentNonce: string;
  deviceId: string;
  keyVersion: number;
  idempotencyKey: string;
  signature: string;
  broadcastMention: boolean;
  mentionedUserIds?: string[];
  refMessageId?: string;
  postId?: string;
  deviceSeq: number;
  seenHeads: SignedEventHead[];
}

/**
 * A message encrypted and signed once. Sending it again repeats the same
 * request, which the server accepts as the same message.
 */
export interface SealedMessage {
  envelope: SignedMessageEnvelope;
  request: SealedMessageRequest;
}

const isString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

/** A v5 binding: null exactly when there is no id to bind, else the signed pair. */
function validBinding(binding: unknown, id: string | undefined): boolean {
  if (binding === undefined) return true;
  if (id === undefined) return binding === null;
  if (!binding || typeof binding !== 'object') return false;
  const { authorId, idempotencyKey } = binding as Record<string, unknown>;
  return isString(authorId) && isString(idempotencyKey);
}

/**
 * Whether a stored sealed message is in a layout older than v6 (saved by an
 * earlier version). The server refuses those, so it is sealed again; if the
 * old request was stored after all, the server says so for its idempotency key.
 */
export function isOutdatedSealedMessage(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  const { envelope, request } = value as { envelope?: Record<string, unknown>; request?: Record<string, unknown> };
  return Boolean(envelope && request && typeof envelope === 'object' && typeof request === 'object')
    && envelope!.deviceSeq === undefined && request!.deviceSeq === undefined;
}

/** Validate a stored sealed message against the command it was made for. */
export function parseSealedMessage(
  value: unknown,
  expected: { channelId: string; idempotencyKey: string; refMessageId?: string; postId?: string },
): SealedMessage | null {
  if (!value || typeof value !== 'object') return null;
  const { envelope, request } = value as { envelope?: Record<string, unknown>; request?: Record<string, unknown> };
  if (!envelope || typeof envelope !== 'object' || !request || typeof request !== 'object') return null;
  const sameFields = (['encryptedContent', 'contentNonce', 'deviceId', 'keyVersion', 'idempotencyKey', 'broadcastMention', 'deviceSeq'] as const)
    .every((field) => envelope[field] === request[field]);
  if (
    !sameFields
    || envelope.type !== 'message'
    || envelope.channelId !== expected.channelId
    || envelope.idempotencyKey !== expected.idempotencyKey
    || !isString(envelope.authorId)
    || !isString(request.encryptedContent)
    || !isString(request.contentNonce)
    || !isString(request.deviceId)
    || !Number.isSafeInteger(request.keyVersion)
    || !isString(request.signature)
    || typeof request.broadcastMention !== 'boolean'
    || (envelope.refMessageId ?? undefined) !== expected.refMessageId
    || (request.refMessageId ?? undefined) !== expected.refMessageId
    || (envelope.postId ?? undefined) !== expected.postId
    || (request.postId ?? undefined) !== expected.postId
    || !validBinding(envelope.refBinding, expected.refMessageId)
    || !validBinding(envelope.postBinding, expected.postId)
    || (envelope.postBinding !== undefined && envelope.refBinding === undefined)
    || envelope.refBinding === undefined
    || (expected.postId !== undefined && envelope.postBinding === undefined)
    || !isDeviceSequence(request.deviceSeq)
    || !isString(request.deviceId)
    || !isValidSeenHeads(envelope.seenHeads, request.deviceId as string)
    || JSON.stringify(envelope.seenHeads) !== JSON.stringify(request.seenHeads)
    || envelope.supersedes !== null
    || (request.mentionedUserIds !== undefined && (
      !Array.isArray(request.mentionedUserIds) || !request.mentionedUserIds.every(isString)
    ))
  ) return null;
  return {
    envelope: { ...envelope } as unknown as SignedMessageEnvelope,
    request: {
      ...request,
      seenHeads: (request.seenHeads as SignedEventHead[]).map((head) => ({ ...head })),
      ...(request.mentionedUserIds ? { mentionedUserIds: [...request.mentionedUserIds as string[]] } : {}),
    } as unknown as SealedMessageRequest,
  };
}
