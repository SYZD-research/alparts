import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/crypto.service', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/crypto.service')>();
  return {
    ...actual,
    ensureChannelKey: vi.fn(),
    startChannelWithoutHistory: vi.fn(),
  };
});

import { api } from '../services/api';
import {
  ChannelKeyDeliveryPendingError,
  ensureChannelKey,
  startChannelWithoutHistory,
} from '../services/crypto.service';
import { useMessageStore } from './message.store';

const channelId = '11111111-1111-4111-8111-111111111111';

afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(ensureChannelKey).mockReset();
  vi.mocked(startChannelWithoutHistory).mockReset();
  useMessageStore.getState().reset();
});

describe('new-device channel preparation', () => {
  it('waits without reporting a security failure, then reloads automatically after delivery', async () => {
    vi.mocked(ensureChannelKey)
      .mockRejectedValueOnce(new ChannelKeyDeliveryPendingError())
      .mockResolvedValue({ key: {} as CryptoKey, version: 1 });
    const getMessages = vi.spyOn(api, 'getMessages').mockResolvedValue({
      data: [],
      hasMore: false,
      cursor: null,
    });

    await useMessageStore.getState().loadMessages(channelId);

    expect(getMessages).not.toHaveBeenCalled();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(true);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeTruthy();
    expect(useMessageStore.getState().securityErrors[channelId]).toBeNull();

    await expect(useMessageStore.getState().retryChannelPreparation(channelId)).resolves.toBe(true);

    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().eventsByChannel[channelId]).toEqual([]);
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeNull();
  });

  it('clears the waiting state and reloads after starting without history', async () => {
    useMessageStore.setState({
      channelKeyPending: { [channelId]: 'waiting' },
      channelRecoveryPending: { [channelId]: true },
      securityErrors: { [channelId]: null },
    });
    vi.mocked(startChannelWithoutHistory).mockResolvedValue({ key: {} as CryptoKey, version: 2 });
    vi.mocked(ensureChannelKey).mockResolvedValue({ key: {} as CryptoKey, version: 2 });
    const getMessages = vi.spyOn(api, 'getMessages').mockResolvedValue({
      data: [],
      hasMore: false,
      cursor: null,
    });

    await useMessageStore.getState().startChannelWithoutHistory(channelId, 'Synthetic-Current-Password-1!');

    expect(startChannelWithoutHistory).toHaveBeenCalledWith(channelId, 'Synthetic-Current-Password-1!');
    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeNull();
  });
});
