import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Message } from '@alparts/shared';
import { api } from '../services/api';
import { MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL, setForumRetention, useMessageStore } from './message.store';

const channelId = '11111111-1111-4111-8111-111111111111';
const messageId = '22222222-2222-4222-8222-222222222222';

afterEach(() => {
  vi.restoreAllMocks();
  useMessageStore.getState().reset();
});

describe('message channel cleanup', () => {
  it('retains only the newest bounded event window for a channel', () => {
    for (let index = 0; index <= MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL; index += 1) {
      useMessageStore.getState().addMessage(channelId, systemEvent(index));
    }
    const retained = useMessageStore.getState().eventsByChannel[channelId];
    expect(retained).toHaveLength(MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL);
    expect(retained[0].id).toBe(systemEvent(1).id);
    expect(retained[retained.length - 1]?.id).toBe(systemEvent(MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL).id);
  });

  it('keeps forum posts on screen even when they are older than the window', () => {
    const listedPost = systemEvent(0);
    const openPost = systemEvent(1);
    const reply = { ...systemEvent(2), postId: openPost.id };
    const rootEdit = { ...systemEvent(3), type: 'edit' as const, postId: listedPost.id, refMessageId: listedPost.id };
    const otherReply = { ...systemEvent(4), postId: listedPost.id };
    setForumRetention(channelId, { rootIds: new Set([listedPost.id, openPost.id]), activePostId: openPost.id });
    useMessageStore.getState().addMessages(channelId, [listedPost, openPost, reply, rootEdit, otherReply]);
    for (let index = 5; index <= MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL + 5; index += 1) {
      useMessageStore.getState().addMessage(channelId, systemEvent(index));
    }

    const ids = useMessageStore.getState().eventsByChannel[channelId].map((event) => event.id);
    expect(ids).toEqual(expect.arrayContaining([listedPost.id, openPost.id, reply.id, rootEdit.id]));
    expect(ids).not.toContain(otherReply.id);
    expect(ids).not.toContain(systemEvent(5).id);
    expect(ids).toContain(systemEvent(MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL + 5).id);

    useMessageStore.getState().clearChannel(channelId);
    useMessageStore.getState().addMessages(channelId, [listedPost]);
    for (let index = 5; index <= MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL + 5; index += 1) {
      useMessageStore.getState().addMessage(channelId, systemEvent(index));
    }
    expect(useMessageStore.getState().eventsByChannel[channelId].map((event) => event.id)).not.toContain(listedPost.id);
  });

  it('does not recreate channel state from a late reaction response', async () => {
    const deferred = promiseWithResolvers<Awaited<ReturnType<typeof api.toggleReaction>>>();
    vi.spyOn(api, 'toggleReaction').mockReturnValue(deferred.promise);
    const operation = useMessageStore.getState().toggleReaction(messageId, '👍', channelId, 'user');

    useMessageStore.getState().clearChannel(channelId);
    deferred.resolve({
      messageId,
      channelId,
      userId: '44444444-4444-4444-8444-444444444444',
      action: 'added',
      emoji: '👍',
      reactions: [],
    });
    await operation;

    expect(useMessageStore.getState().eventsByChannel).not.toHaveProperty(channelId);
    expect(useMessageStore.getState().operationErrors).not.toHaveProperty(channelId);
  });

  it('does not recreate channel state from a late pin failure', async () => {
    const deferred = promiseWithResolvers<Awaited<ReturnType<typeof api.pinMessage>>>();
    vi.spyOn(api, 'pinMessage').mockReturnValue(deferred.promise);
    const operation = useMessageStore.getState().pinMessage(messageId, channelId);

    useMessageStore.getState().clearChannel(channelId);
    deferred.reject(new Error('late failure'));
    await expect(operation).rejects.toThrow('late failure');

    expect(useMessageStore.getState().eventsByChannel).not.toHaveProperty(channelId);
    expect(useMessageStore.getState().operationErrors).not.toHaveProperty(channelId);
  });
});

function systemEvent(index: number): Message {
  const suffix = index.toString(16).padStart(12, '0');
  return {
    id: `00000000-0000-4000-8000-${suffix}`,
    channelId,
    authorId: '33333333-3333-4333-8333-333333333333',
    author: {
      id: '33333333-3333-4333-8333-333333333333',
      displayName: 'System',
      avatarUrl: null,
      status: 'offline',
      createdAt: '2026-01-01T00:00:00.000Z',
    },
    deviceId: null,
    content: `event-${index}`,
    encryptedContent: '',
    contentNonce: '',
    keyVersion: 0,
    signature: null,
    type: 'system',
    refMessageId: null,
    reactions: [],
    isPinned: false,
    idempotencyKey: `system-${index}`,
    createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
  };
}

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
