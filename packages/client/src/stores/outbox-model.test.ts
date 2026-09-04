import { describe, expect, it } from 'vitest';
import {
  createOutboxCommand,
  outboxItemFromCommand,
  parseOutboxCommand,
  transitionOutboxItem,
} from './outbox-model';

describe('outbox command', () => {
  it('creates the idempotency key once and preserves it through encrypted-storage serialization', () => {
    const mentionedUserA = '10000000-0000-4000-8000-000000000001';
    const mentionedUserB = '10000000-0000-4000-8000-000000000002';
    let idCalls = 0;
    const command = createOutboxCommand(
      {
        channelId: 'channel-1',
        content: 'hello',
        refMessageId: 'message-1',
        mentionedUserIds: [mentionedUserB, mentionedUserA, mentionedUserA],
      },
      () => { idCalls += 1; return 'fixed-idempotency-key'; },
      () => '2026-01-01T00:00:00.000Z',
    );
    const restored = parseOutboxCommand(JSON.parse(JSON.stringify(command)));

    expect(idCalls).toBe(1);
    expect(restored?.idempotencyKey).toBe('fixed-idempotency-key');
    expect(restored?.mentionedUserIds).toEqual([mentionedUserA, mentionedUserB]);
    expect(restored).toEqual(command);
  });

  it('rejects malformed decrypted records', () => {
    expect(parseOutboxCommand({ version: 1, channelId: 'channel-1', content: 'hello' })).toBeNull();
    expect(parseOutboxCommand({
      version: 1,
      idempotencyKey: 'key',
      channelId: 'channel-1',
      content: 'hello',
      mentionedUserIds: ['not-a-user-id'],
      createdAt: '2026-01-01T00:00:00.000Z',
    })).toBeNull();
  });

  it('keeps the optimistic preview while moving through queued, sending, and failed states', () => {
    const command = createOutboxCommand(
      { channelId: 'channel-1', content: 'visible pending message' },
      () => 'fixed-id',
      () => '2026-01-01T00:00:00.000Z',
    );
    const queued = outboxItemFromCommand(command);
    const sending = transitionOutboxItem(queued, { type: 'send' });
    const failed = transitionOutboxItem(sending, { type: 'fail', error: 'network unavailable' });
    const retried = transitionOutboxItem(failed, { type: 'queue' });

    expect([queued.status, sending.status, failed.status, retried.status]).toEqual([
      'queued', 'sending', 'failed', 'queued',
    ]);
    expect(failed).toMatchObject({ content: command.content, id: command.idempotencyKey, error: 'network unavailable' });
    expect(retried.error).toBeNull();
  });
});
