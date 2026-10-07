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
    expect(useMessageStore.getState().channelKeyPending[channelId]).toEqual({ reason: 'waiting', freshStartAvailable: false });
    expect(useMessageStore.getState().securityErrors[channelId]).toBeNull();

    await expect(useMessageStore.getState().retryChannelPreparation(channelId)).resolves.toBe(true);

    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().eventsByChannel[channelId]).toEqual([]);
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeNull();
  });

  it('keeps showing history while the device asks to be added again or a first group waits', async () => {
    const getMessages = vi.spyOn(api, 'getMessages').mockResolvedValue({ data: [], hasMore: false, cursor: null });
    vi.mocked(ensureChannelKey).mockRejectedValueOnce(new ChannelKeyDeliveryPendingError('rejoining'));
    await useMessageStore.getState().loadMessages(channelId);
    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toEqual({ reason: 'rejoining', freshStartAvailable: false });

    vi.mocked(ensureChannelKey).mockRejectedValueOnce(new ChannelKeyDeliveryPendingError('genesis-waiting'));
    expect(await useMessageStore.getState().reconcileChannelKey(channelId)).toBe(false);
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toEqual({ reason: 'genesis-waiting', freshStartAvailable: false });
    expect(useMessageStore.getState().securityErrors[channelId]).toBeNull();

    vi.mocked(ensureChannelKey).mockResolvedValue({ key: {} as CryptoKey, version: 3 });
    expect(await useMessageStore.getState().reconcileChannelKey(channelId)).toBe(true);
    expect(useMessageStore.getState().channelKeyPending[channelId]).toBeNull();
  });

  it('keeps history and only stops sending when the device may no longer ask to be added again', async () => {
    const getMessages = vi.spyOn(api, 'getMessages').mockResolvedValue({ data: [], hasMore: false, cursor: null });
    vi.mocked(ensureChannelKey).mockRejectedValueOnce(new ChannelKeyDeliveryPendingError('unavailable', true));
    await useMessageStore.getState().loadMessages(channelId);
    // Loading only reads: due removals and refreshes are left to writers.
    expect(ensureChannelKey).toHaveBeenCalledWith(channelId, { purpose: 'read' });
    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
    expect(useMessageStore.getState().securityErrors[channelId]).toBeNull();
    expect(useMessageStore.getState().channelKeyPending[channelId]).toEqual({ reason: 'unavailable', freshStartAvailable: true });
  });

  it('loads messages once a device that was waiting to be added is asked to rejoin instead', async () => {
    const getMessages = vi.spyOn(api, 'getMessages').mockResolvedValue({ data: [], hasMore: false, cursor: null });
    vi.mocked(ensureChannelKey).mockRejectedValueOnce(new ChannelKeyDeliveryPendingError('waiting'));
    await useMessageStore.getState().loadMessages(channelId);
    expect(getMessages).not.toHaveBeenCalled();
    vi.mocked(ensureChannelKey).mockRejectedValue(new ChannelKeyDeliveryPendingError('rejoining'));
    expect(await useMessageStore.getState().retryChannelPreparation(channelId)).toBe(false);
    expect(getMessages).toHaveBeenCalledOnce();
    expect(useMessageStore.getState().channelRecoveryPending[channelId]).toBe(false);
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
      channelKeyPending: { [channelId]: { reason: 'waiting', freshStartAvailable: true } },
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
