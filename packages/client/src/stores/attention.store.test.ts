import { beforeEach, describe, expect, it } from 'vitest';
import { useAttentionStore } from './attention.store';

const base = {
  notificationId: '00000000-0000-4000-8000-000000000001',
  workspaceId: '00000000-0000-4000-8000-000000000002',
  channelId: '00000000-0000-4000-8000-000000000003',
};

describe('attention store', () => {
  beforeEach(() => useAttentionStore.getState().reset());

  it('keeps a restarted-channel notice for a channel the manager cannot see', () => {
    useAttentionStore.getState().add({ ...base, kind: 'channel-restarted' });
    expect(useAttentionStore.getState().items.map((item) => item.kind)).toEqual(['channel-restarted']);
  });

  it('still drops a mention for a channel without local state', () => {
    useAttentionStore.getState().add({ ...base, kind: 'mention' });
    expect(useAttentionStore.getState().items).toEqual([]);
  });
});
