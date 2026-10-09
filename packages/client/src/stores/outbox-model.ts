import { MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE, type SignedEventReference } from '@alparts/shared';
import { parseSealedMessage, type SealedMessage } from './sealed-message';

export interface OutboxCommand {
  version: 1;
  idempotencyKey: string;
  channelId: string;
  content: string;
  refMessageId?: string;
  /** Forum replies: the post the reply is signed for. */
  postId?: string;
  /** The quoted message and the post as their authors signed them, saved when queued. */
  refBinding?: SignedEventReference;
  postBinding?: SignedEventReference;
  mentionedUserIds?: string[];
  createdAt: string;
  /**
   * The signed request, saved before it is first sent. Every later attempt,
   * including after a restart, sends exactly this request.
   */
  sealed?: SealedMessage;
  /** Automatic reseals after the server asked for a newer key (at most MAX_AUTOMATIC_RESEALS). */
  resealCount?: number;
  /** Why the server last refused this message as sent, if it gave a reason. */
  lastRefusal?: string;
}

export const MAX_OUTBOX_COMMANDS_PER_DEVICE = 100;
/** A refused message is sealed again with a newer key this often before it waits for the user. */
export const MAX_AUTOMATIC_RESEALS = 3;
/** Refusals that a newer key resolves: the version moved on, or a removal is due first. */
const RESEALABLE_REASONS = new Set(['KEY_VERSION_STALE', 'KEY_ROTATION_REQUIRED']);

/** Whether a refused message is sealed again automatically. */
export function shouldResealAutomatically(reason: string | null, resealCount = 0): boolean {
  return isKeyRefusal(reason) && resealCount < MAX_AUTOMATIC_RESEALS;
}

/** A refusal that a newer key on this device resolves. */
export function isKeyRefusal(reason: string | null | undefined): boolean {
  return typeof reason === 'string' && RESEALABLE_REASONS.has(reason);
}
const REFUSAL_PATTERN = /^[A-Z_]{1,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type OutboxStatus = 'queued' | 'sending' | 'failed';

export interface OutboxItem {
  id: string;
  channelId: string;
  content: string;
  refMessageId?: string;
  postId?: string;
  mentionedUserIds?: string[];
  createdAt: string;
  status: OutboxStatus;
  error: string | null;
  /** Why the server last refused it, if it gave a reason. */
  lastRefusal?: string;
}

export type OutboxTransition =
  | { type: 'queue'; error?: string | null }
  | { type: 'send' }
  | { type: 'fail'; error: string };

interface CreateOutboxCommandInput {
  channelId: string;
  content: string;
  refMessageId?: string;
  postId?: string;
  refBinding?: SignedEventReference;
  postBinding?: SignedEventReference;
  mentionedUserIds?: string[];
}

function isReference(value: unknown): value is SignedEventReference {
  if (!value || typeof value !== 'object') return false;
  const { authorId, idempotencyKey } = value as Record<string, unknown>;
  return typeof authorId === 'string' && authorId.length > 0 && typeof idempotencyKey === 'string' && idempotencyKey.length > 0;
}

export function createOutboxCommand(
  input: CreateOutboxCommandInput,
  createId: () => string = () => crypto.randomUUID(),
  now: () => string = () => new Date().toISOString(),
): OutboxCommand {
  const mentionedUserIds = [...new Set(input.mentionedUserIds || [])]
    .sort()
    .slice(0, MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE);
  return {
    version: 1,
    idempotencyKey: createId(),
    channelId: input.channelId,
    content: input.content,
    ...(input.refMessageId ? { refMessageId: input.refMessageId } : {}),
    ...(input.postId ? { postId: input.postId } : {}),
    ...(input.refMessageId && input.refBinding ? { refBinding: { ...input.refBinding } } : {}),
    ...(input.postId && input.postBinding ? { postBinding: { ...input.postBinding } } : {}),
    ...(mentionedUserIds.length ? { mentionedUserIds } : {}),
    createdAt: now(),
  };
}

/** Validate decrypted IndexedDB data before it reaches the send path. */
export function parseOutboxCommand(value: unknown): OutboxCommand | null {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<OutboxCommand>;
  if (
    candidate.version !== 1
    || typeof candidate.idempotencyKey !== 'string'
    || typeof candidate.channelId !== 'string'
    || typeof candidate.content !== 'string'
    || typeof candidate.createdAt !== 'string'
    || (candidate.refMessageId !== undefined && typeof candidate.refMessageId !== 'string')
    || (candidate.lastRefusal !== undefined && (
      typeof candidate.lastRefusal !== 'string' || !REFUSAL_PATTERN.test(candidate.lastRefusal)
    ))
    || (candidate.resealCount !== undefined && (
      !Number.isSafeInteger(candidate.resealCount)
      || candidate.resealCount < 0
      || candidate.resealCount > MAX_AUTOMATIC_RESEALS
    ))
    || (candidate.postId !== undefined && (typeof candidate.postId !== 'string' || !UUID_PATTERN.test(candidate.postId)))
    || (candidate.refBinding !== undefined && (candidate.refMessageId === undefined || !isReference(candidate.refBinding)))
    || (candidate.postBinding !== undefined && (candidate.postId === undefined || !isReference(candidate.postBinding)))
    || (candidate.mentionedUserIds !== undefined && (
      !Array.isArray(candidate.mentionedUserIds)
      || candidate.mentionedUserIds.length > MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE
      || candidate.mentionedUserIds.some((userId) => typeof userId !== 'string' || !UUID_PATTERN.test(userId))
      || new Set(candidate.mentionedUserIds).size !== candidate.mentionedUserIds.length
    ))
  ) return null;
  if (candidate.sealed === undefined) return candidate as OutboxCommand;
  const sealed = parseSealedMessage(candidate.sealed, {
    channelId: candidate.channelId,
    idempotencyKey: candidate.idempotencyKey,
    ...(candidate.refMessageId ? { refMessageId: candidate.refMessageId } : {}),
    ...(candidate.postId ? { postId: candidate.postId } : {}),
  });
  return sealed ? { ...candidate, sealed } as OutboxCommand : null;
}

export function outboxItemFromCommand(command: OutboxCommand): OutboxItem {
  return {
    id: command.idempotencyKey,
    channelId: command.channelId,
    content: command.content,
    ...(command.refMessageId ? { refMessageId: command.refMessageId } : {}),
    ...(command.postId ? { postId: command.postId } : {}),
    ...(command.mentionedUserIds?.length ? { mentionedUserIds: [...command.mentionedUserIds] } : {}),
    createdAt: command.createdAt,
    status: 'queued',
    error: null,
    ...(command.lastRefusal ? { lastRefusal: command.lastRefusal } : {}),
  };
}

export function transitionOutboxItem(item: OutboxItem, transition: OutboxTransition): OutboxItem {
  if (transition.type === 'send') return { ...item, status: 'sending', error: null };
  if (transition.type === 'fail') return { ...item, status: 'failed', error: transition.error };
  return { ...item, status: 'queued', error: transition.error ?? null };
}
