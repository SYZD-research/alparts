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
  it('ignores a late history page after an initial refresh and preserves loading for other channels', async () => {
    vi.mocked(ensureChannelKey).mockResolvedValue({ key: {} as CryptoKey, version: 1 });
    const deferred = () => {
      let resolve!: (value: { data: []; hasMore: boolean; cursor: string | null }) => void;
      const promise = new Promise<{ data: []; hasMore: boolean; cursor: string | null }>((done) => { resolve = done; });
      return { promise, resolve };
    };
    const page = deferred();
    const other = deferred();
    vi.spyOn(api, 'getMessages').mockImplementation((id, cursor) => {
      if (cursor) return page.promise;
      if (id !== channelId) return other.promise;
      return Promise.resolve({ data: [], hasMore: true, cursor: 'fresh-cursor' });
    });
    useMessageStore.setState({ hasMore: { [channelId]: true }, cursors: { [channelId]: 'old-cursor' } });
    const paging = useMessageStore.getState().loadMoreMessages(channelId);
    const otherLoad = useMessageStore.getState().loadMessages('other-channel');
    await useMessageStore.getState().loadMessages(channelId);
    expect(useMessageStore.getState().isLoading).toBe(true);
    page.resolve({ data: [], hasMore: false, cursor: null });
    await paging;
    expect(useMessageStore.getState().cursors[channelId]).toBe('fresh-cursor');
    expect(useMessageStore.getState().hasMore[channelId]).toBe(true);
    other.resolve({ data: [], hasMore: false, cursor: null });
    await otherLoad;
    expect(useMessageStore.getState().isLoading).toBe(false);
  });

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

  it('clears a transient preparation failure after a verified reconciliation', async () => {
    vi.mocked(ensureChannelKey).mockRejectedValueOnce(new Error('temporary failure'))
      .mockResolvedValue({ key: {} as CryptoKey, version: 2 });
    expect(await useMessageStore.getState().reconcileChannelKey(channelId)).toBe(false);
    expect(useMessageStore.getState().securityErrors[channelId]).toBe('temporary failure');
    expect(await useMessageStore.getState().reconcileChannelKey(channelId)).toBe(true);
    expect(useMessageStore.getState().securityErrors[channelId]).toBeNull();
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

    await useMessageStore.getState().startChannelWithoutHistory(channelId);

    expect(startChannelWithoutHistory).toHaveBeenCalledWith(channelId);
    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeNull();
  });
});
