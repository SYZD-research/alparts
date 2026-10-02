import type { SignedMessageEnvelope } from '@alparts/shared';

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

/** Validate a stored sealed message against the command it was made for. */
export function parseSealedMessage(
  value: unknown,
  expected: { channelId: string; idempotencyKey: string; refMessageId?: string; postId?: string },
): SealedMessage | null {
  if (!value || typeof value !== 'object') return null;
  const { envelope, request } = value as { envelope?: Record<string, unknown>; request?: Record<string, unknown> };
  if (!envelope || typeof envelope !== 'object' || !request || typeof request !== 'object') return null;
  const sameFields = (['encryptedContent', 'contentNonce', 'deviceId', 'keyVersion', 'idempotencyKey', 'broadcastMention'] as const)
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
    || (request.mentionedUserIds !== undefined && (
      !Array.isArray(request.mentionedUserIds) || !request.mentionedUserIds.every(isString)
    ))
  ) return null;
  return {
    envelope: { ...envelope } as unknown as SignedMessageEnvelope,
    request: { ...request, ...(request.mentionedUserIds ? { mentionedUserIds: [...request.mentionedUserIds as string[]] } : {}) } as unknown as SealedMessageRequest,
  };
}
