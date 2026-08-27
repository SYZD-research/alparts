import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../services/api';
import { useMessageStore } from './message.store';

const channelId = '11111111-1111-4111-8111-111111111111';
const messageId = '22222222-2222-4222-8222-222222222222';

afterEach(() => {
  vi.restoreAllMocks();
  useMessageStore.getState().reset();
});

describe('message channel cleanup', () => {
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
