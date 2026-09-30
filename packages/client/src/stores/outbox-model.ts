import { MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE } from '@alparts/shared';

export interface OutboxCommand {
  version: 1;
  idempotencyKey: string;
  channelId: string;
  content: string;
  refMessageId?: string;
  /** Forum replies: the post the reply is signed for. */
  postId?: string;
  mentionedUserIds?: string[];
  createdAt: string;
}

export const MAX_OUTBOX_COMMANDS_PER_DEVICE = 100;
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
  mentionedUserIds?: string[];
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
    || (candidate.postId !== undefined && (typeof candidate.postId !== 'string' || !UUID_PATTERN.test(candidate.postId)))
    || (candidate.mentionedUserIds !== undefined && (
      !Array.isArray(candidate.mentionedUserIds)
      || candidate.mentionedUserIds.length > MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE
      || candidate.mentionedUserIds.some((userId) => typeof userId !== 'string' || !UUID_PATTERN.test(userId))
      || new Set(candidate.mentionedUserIds).size !== candidate.mentionedUserIds.length
    ))
  ) return null;
  return candidate as OutboxCommand;
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
  };
}

export function transitionOutboxItem(item: OutboxItem, transition: OutboxTransition): OutboxItem {
  if (transition.type === 'send') return { ...item, status: 'sending', error: null };
  if (transition.type === 'fail') return { ...item, status: 'failed', error: transition.error };
  return { ...item, status: 'queued', error: transition.error ?? null };
}
