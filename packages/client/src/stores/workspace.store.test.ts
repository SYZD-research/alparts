import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { WorkspaceMember } from '@alparts/shared';

const mocks = vi.hoisted(() => ({
  api: {
    getWorkspaceMembers: vi.fn(),
    getWarnedUsers: vi.fn(),
  },
  seedStatuses: vi.fn(),
}));

vi.mock('../services/api', () => ({ api: mocks.api }));
vi.mock('./channel.store', () => ({ useChannelStore: { getState: () => ({ reset: vi.fn() }) } }));
vi.mock('./message.store', () => ({ useMessageStore: { getState: () => ({ reset: vi.fn() }) } }));
vi.mock('./presence.store', () => ({ usePresenceStore: { getState: () => ({ seedStatuses: mocks.seedStatuses }) } }));

import { useWorkspaceStore } from './workspace.store';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

const member = (userId: string) => ({ userId, user: { id: userId, displayName: userId, status: 'online' } }) as unknown as WorkspaceMember;

beforeEach(() => {
  useWorkspaceStore.getState().reset();
  useWorkspaceStore.setState({ activeWorkspaceId: 'w' });
  vi.clearAllMocks();
});

describe('member list requests that finish out of order (SQ-03)', () => {
  it('keeps the list and warnings of the newest request', async () => {
    const olderMembers = deferred<WorkspaceMember[]>();
    const olderWarned = deferred<{ userIds: string[]; complete: boolean }>();
    mocks.api.getWorkspaceMembers.mockReturnValueOnce(olderMembers.promise).mockResolvedValueOnce([member('a'), member('b')]);
    mocks.api.getWarnedUsers.mockReturnValueOnce(olderWarned.promise).mockResolvedValueOnce({ userIds: ['b'], complete: true });

    const older = useWorkspaceStore.getState().loadMembers('w');
    await useWorkspaceStore.getState().loadMembers('w');
    olderMembers.resolve([member('a')]);
    olderWarned.resolve({ userIds: [], complete: true });
    await older;

    const state = useWorkspaceStore.getState();
    expect(state.members.map((candidate) => candidate.userId)).toEqual(['a', 'b']);
    expect([...state.warnedUsers!.ids]).toEqual(['b']);
  });
});
