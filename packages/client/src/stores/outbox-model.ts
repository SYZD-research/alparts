export interface OutboxCommand {
  version: 1;
  idempotencyKey: string;
  channelId: string;
  content: string;
  refMessageId?: string;
  createdAt: string;
}

export const MAX_OUTBOX_COMMANDS_PER_DEVICE = 100;

export type OutboxStatus = 'queued' | 'sending' | 'failed';

export interface OutboxItem {
  id: string;
  channelId: string;
  content: string;
  refMessageId?: string;
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
}

export function createOutboxCommand(
  input: CreateOutboxCommandInput,
  createId: () => string = () => crypto.randomUUID(),
  now: () => string = () => new Date().toISOString(),
): OutboxCommand {
  return {
    version: 1,
    idempotencyKey: createId(),
    channelId: input.channelId,
    content: input.content,
    ...(input.refMessageId ? { refMessageId: input.refMessageId } : {}),
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
  ) return null;
  return candidate as OutboxCommand;
}

export function outboxItemFromCommand(command: OutboxCommand): OutboxItem {
  return {
    id: command.idempotencyKey,
    channelId: command.channelId,
    content: command.content,
    ...(command.refMessageId ? { refMessageId: command.refMessageId } : {}),
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
