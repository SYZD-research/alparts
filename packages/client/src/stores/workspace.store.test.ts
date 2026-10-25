import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { WorkspaceMember } from '@alparts/shared';

const mocks = vi.hoisted(() => ({
  api: {
    getWorkspaceMembers: vi.fn(),
    getWarnedUsers: vi.fn(),
    createWorkspace: vi.fn(),
    getCategories: vi.fn(),
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

describe('creating a workspace', () => {
  it('opens it, and lists it once when a reload already brought it in', async () => {
    const created = { id: 'new', name: 'New', iconUrl: null, ownerId: 'a', createdAt: '2026-10-25T00:00:00.000Z' };
    useWorkspaceStore.setState({ activeWorkspaceId: null, workspaces: [] });
    mocks.api.createWorkspace.mockImplementation(async () => {
      // A membership event reloaded the list before the creation answered.
      useWorkspaceStore.setState({ workspaces: [created] });
      return created;
    });
    mocks.api.getCategories.mockResolvedValue([]);
    mocks.api.getWorkspaceMembers.mockResolvedValue([]);

    await useWorkspaceStore.getState().createWorkspace('New');

    const state = useWorkspaceStore.getState();
    expect(state.workspaces.map((workspace) => workspace.id)).toEqual(['new']);
    expect(state.activeWorkspaceId).toBe('new');
  });
});

describe('a member who changed their profile', () => {
  it('shows the new name and picture for that member only', () => {
    useWorkspaceStore.setState({ members: [member('a'), member('b')] });

    useWorkspaceStore.getState().updateMemberProfile('b', { displayName: 'B renamed', avatarUrl: '/avatar/b/2' });

    const users = useWorkspaceStore.getState().members.map((candidate) => [candidate.userId, candidate.user.displayName, candidate.user.avatarUrl]);
    expect(users).toEqual([['a', 'a', undefined], ['b', 'B renamed', '/avatar/b/2']]);
  });
});
