import { describe, expect, it } from 'vitest';
import { serializeMessageEnvelope, type Message } from '@alparts/shared';
import { signedEnvelopeCandidates } from './message-envelope';

const pair = { authorId: 'user-2', idempotencyKey: 'k-target' };

function served(fields: Partial<Message>): Message {
  return {
    id: 'event-1',
    channelId: '11111111-1111-4111-8111-111111111111',
    authorId: 'user-1',
    author: { id: 'user-1', email: 'alice@example.test', displayName: 'Alice', avatarUrl: null, status: 'online', createdAt: '2026-01-01T00:00:00.000Z' },
    deviceId: 'device-1',
    content: '',
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type: 'message',
    refMessageId: null,
    broadcastMention: false,
    reactions: [],
    isPinned: false,
    idempotencyKey: 'k-event',
    createdAt: '2026-01-01T00:00:00.000Z',
    ...fields,
  } as Message;
}

const layouts = (message: Message, forum: boolean) => signedEnvelopeCandidates(message, forum)
  .map((envelope) => JSON.parse(serializeMessageEnvelope(envelope))[0] as number);

describe('signed layouts a served event may verify in (formal model M9)', () => {
  it('accepts an edit, a deletion or a quote only in v5', () => {
    for (const type of ['edit', 'delete', 'message'] as const) {
      expect(layouts(served({ type, refMessageId: 'target', refBinding: pair }), false)).toEqual([5]);
    }
  });

  it('accepts a forum event inside a post only in v5', () => {
    expect(layouts(served({ postId: 'post', refBinding: null, postBinding: pair }), true)).toEqual([5]);
    expect(layouts(served({ type: 'edit', refMessageId: 'post', postId: 'post', refBinding: pair, postBinding: pair }), true)).toEqual([5]);
  });

  it('tries nothing that names a reference without what it names', () => {
    // Without the served pair the v5 envelope cannot even be formed, so the event does not verify.
    const [only] = signedEnvelopeCandidates(served({ type: 'edit', refMessageId: 'target' }), false);
    expect(() => serializeMessageEnvelope(only!)).toThrow(/INVALID_BOUND_ENVELOPE/);
  });

  it('keeps both layouts for an event that names no other message', () => {
    expect(layouts(served({}), false)).toEqual([3, 5]);
    expect(layouts(served({ postId: null }), true)).toEqual([4, 5]);
  });
});
