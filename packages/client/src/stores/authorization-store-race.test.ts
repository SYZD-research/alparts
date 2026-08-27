import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Channel, Workspace } from '@alparts/shared';
import { api } from '../services/api';
import { useChannelStore } from './channel.store';
import { useWorkspaceStore } from './workspace.store';

const workspace: Workspace = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Workspace',
  iconUrl: null,
  ownerId: '22222222-2222-4222-8222-222222222222',
  createdAt: '2026-01-01T00:00:00.000Z',
};
const channel: Channel = {
  id: '33333333-3333-4333-8333-333333333333',
  workspaceId: workspace.id,
  categoryId: null,
  name: 'channel',
  type: 'text',
  isPrivate: false,
  topic: null,
  position: 0,
  createdAt: '2026-01-01T00:00:00.000Z',
};

afterEach(() => {
  vi.restoreAllMocks();
  useChannelStore.getState().reset();
  useWorkspaceStore.getState().reset();
});

describe('authorization list response races', () => {
  it('does not restore a channel from a request started before direct cleanup', async () => {
    useChannelStore.setState({ workspaceId: workspace.id, channels: [channel], activeChannelId: channel.id });
    const deferred = promiseWithResolvers<Channel[]>();
    vi.spyOn(api, 'getChannels').mockReturnValue(deferred.promise);
    const loading = useChannelStore.getState().loadChannels(workspace.id);

    useChannelStore.getState().removeChannel(channel.id);
    deferred.resolve([channel]);
    await loading;

    expect(useChannelStore.getState().channels).toEqual([]);
    expect(useChannelStore.getState().activeChannelId).toBeNull();
  });

  it('does not re-add a workspace from a request started before direct cleanup', async () => {
    useWorkspaceStore.setState({ workspaces: [workspace], activeWorkspaceId: null });
    const deferred = promiseWithResolvers<Workspace[]>();
    vi.spyOn(api, 'getWorkspaces').mockReturnValue(deferred.promise);
    const loading = useWorkspaceStore.getState().loadWorkspaces();

    useWorkspaceStore.getState().removeWorkspace(workspace.id);
    deferred.resolve([workspace]);
    await loading;

    expect(useWorkspaceStore.getState().workspaces).toEqual([]);
  });
});

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
