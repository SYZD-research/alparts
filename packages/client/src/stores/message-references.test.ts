import { afterEach, describe, expect, it, vi } from 'vitest';
import { serializeMessageEnvelope, type Channel, type Message } from '@alparts/shared';

vi.mock('../services/crypto.service', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/crypto.service')>();
  return {
    ...actual,
    ensureChannelKey: vi.fn(async () => ({ key: {} as CryptoKey, version: 1 })),
    getActiveDevice: vi.fn(() => ({ userId: 'user-1', deviceId: 'device-1' })),
    encryptMessage: vi.fn(async () => ({ encrypted: 'ciphertext', nonce: 'nonce' })),
    signMessageEnvelope: vi.fn(async () => 'signature'),
  };
});

import { markMessageCryptoVerification } from './message-projector';
import { useChannelStore } from './channel.store';
import { useMessageStore } from './message.store';

const textId = '11111111-1111-4111-8111-111111111111';
const forumId = '22222222-2222-4222-8222-222222222222';
const postId = '33333333-3333-4333-8333-333333333333';

function loaded(channelId: string, id: string, idempotencyKey: string | undefined): Message {
  return markMessageCryptoVerification({
    id,
    channelId,
    authorId: 'user-2',
    author: { id: 'user-2', email: 'bob@example.test', displayName: 'Bob', avatarUrl: null, status: 'online', createdAt: '2026-01-01T00:00:00.000Z' },
    deviceId: 'device-2',
    content: 'hello',
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type: 'message',
    refMessageId: null,
    ...(channelId === forumId ? { postId: null } : {}),
    reactions: [],
    isPinned: false,
    idempotencyKey,
    createdAt: '2026-01-01T00:00:00.000Z',
  } as Message, true);
}

afterEach(() => {
  useMessageStore.getState().reset();
  useChannelStore.setState({ channels: [] });
});

describe('envelope layouts (formal model M9)', () => {
  it('signs a message without references in the older layout, which clients that were not updated verify', async () => {
    const sealed = await useMessageStore.getState().sealMessage(textId, 'hello');
    expect(sealed.envelope.refBinding).toBeUndefined();
    expect(serializeMessageEnvelope(sealed.envelope)).toMatch(/^\[3,/);
  });

  it('signs a quote in v5, naming the quoted message by its author and key', async () => {
    useMessageStore.setState({ eventsByChannel: { [textId]: [loaded(textId, 'quoted', 'k-quoted')] } });
    const sealed = await useMessageStore.getState().sealMessage(textId, 'ok', { refMessageId: 'quoted' });
    expect(sealed.envelope.refBinding).toEqual({ authorId: 'user-2', idempotencyKey: 'k-quoted' });
    expect(serializeMessageEnvelope(sealed.envelope)).toMatch(/^\[5,"text","message",/);
  });

  it('keeps the older layout for a quote of a message sent before idempotency keys were signed', async () => {
    useMessageStore.setState({ eventsByChannel: { [textId]: [loaded(textId, 'quoted', undefined)] } });
    const sealed = await useMessageStore.getState().sealMessage(textId, 'ok', { refMessageId: 'quoted' });
    expect(sealed.envelope.refBinding).toBeUndefined();
    expect(serializeMessageEnvelope(sealed.envelope)).toMatch(/^\[3,/);
  });

  it('signs a forum reply in v5, naming the post by its first message', async () => {
    useChannelStore.setState({ channels: [{ id: forumId, type: 'forum' } as Channel] });
    useMessageStore.setState({ eventsByChannel: { [forumId]: [loaded(forumId, postId, 'k-post')] } });
    const sealed = await useMessageStore.getState().sealMessage(forumId, 'answer', { postId });
    expect(sealed.envelope.postBinding).toEqual({ authorId: 'user-2', idempotencyKey: 'k-post' });
    expect(sealed.envelope.refBinding).toBeNull();
    expect(serializeMessageEnvelope(sealed.envelope)).toMatch(/^\[5,"forum","message",/);
  });
});
