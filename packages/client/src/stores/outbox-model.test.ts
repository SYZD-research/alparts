import { describe, expect, it } from 'vitest';
import {
  createOutboxCommand,
  isKeyRefusal,
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

  it('keeps the last refusal reason and tells refusals a newer key resolves', () => {
    const command = createOutboxCommand({ channelId: 'channel-1', content: 'hello' });
    expect(parseOutboxCommand({ ...command, lastRefusal: 'KEY_VERSION_STALE' })?.lastRefusal).toBe('KEY_VERSION_STALE');
    expect(outboxItemFromCommand({ ...command, lastRefusal: 'KEY_VERSION_STALE' }).lastRefusal).toBe('KEY_VERSION_STALE');
    expect(parseOutboxCommand({ ...command, lastRefusal: 'not a reason' })).toBeNull();
    expect(isKeyRefusal('KEY_VERSION_STALE')).toBe(true);
    expect(isKeyRefusal('KEY_ROTATION_REQUIRED')).toBe(true);
    expect(isKeyRefusal('INVALID_KEY_VERSION')).toBe(false);
    expect(isKeyRefusal(undefined)).toBe(false);
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

describe('stored signed request (SQ-23)', () => {
  const command = createOutboxCommand({ channelId: 'channel-1', content: 'hello' }, () => 'key-1', () => '2026-01-01T00:00:00.000Z');
  const sealed = {
    envelope: {
      type: 'message', channelId: 'channel-1', authorId: 'user', deviceId: 'device', encryptedContent: 'ciphertext',
      contentNonce: 'nonce', keyVersion: 2, idempotencyKey: 'key-1', refMessageId: null, broadcastMention: false,
    },
    request: {
      encryptedContent: 'ciphertext', contentNonce: 'nonce', deviceId: 'device', keyVersion: 2,
      idempotencyKey: 'key-1', signature: 'signature', broadcastMention: false,
    },
  };

  it('keeps a request that matches its command', () => {
    expect(parseOutboxCommand(JSON.parse(JSON.stringify({ ...command, sealed })))?.sealed).toEqual(sealed);
  });

  it('rejects a request made for another message or altered after signing', () => {
    expect(parseOutboxCommand({ ...command, sealed: { ...sealed, envelope: { ...sealed.envelope, idempotencyKey: 'key-2' } } })).toBeNull();
    expect(parseOutboxCommand({ ...command, sealed: { ...sealed, envelope: { ...sealed.envelope, channelId: 'channel-2' } } })).toBeNull();
    expect(parseOutboxCommand({ ...command, sealed: { ...sealed, request: { ...sealed.request, encryptedContent: 'other' } } })).toBeNull();
    expect(parseOutboxCommand({ ...command, sealed: { ...sealed, request: { ...sealed.request, postId: 'post' } } })).toBeNull();
  });
});
