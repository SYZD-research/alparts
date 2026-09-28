import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../services/api';
import { useWorkspaceStore } from './workspace.store';
import { useChannelStore } from './channel.store';
import { usePresenceStore } from './presence.store';

afterEach(() => {
  useWorkspaceStore.getState().reset();
  usePresenceStore.getState().reset();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('audit loading and typing regressions', () => {
  it('clears a revoked list request without hiding an unrelated workspace selection', async () => {
    let resolveList!: (value: []) => void;
    let resolveMembers!: (value: []) => void;
    vi.spyOn(api, 'getWorkspaces').mockImplementation(() => new Promise((resolve) => { resolveList = resolve; }));
    vi.spyOn(api, 'getCategories').mockResolvedValue([]);
    vi.spyOn(api, 'getWorkspaceMembers').mockImplementation(() => new Promise((resolve) => { resolveMembers = resolve; }));
    vi.spyOn(useChannelStore.getState(), 'loadChannels').mockResolvedValue([]);
    const list = useWorkspaceStore.getState().loadWorkspaces();
    const selection = useWorkspaceStore.getState().setActiveWorkspace('selected');
    useWorkspaceStore.getState().removeWorkspace('revoked');
    expect(useWorkspaceStore.getState().isLoading).toBe(true);
    resolveMembers([]);
    await selection;
    expect(useWorkspaceStore.getState().isLoading).toBe(false);
    resolveList([]);
    expect(await list).toBeNull();
  });

  it('expires lost typing-stop events, refreshes active typing and cancels revoked timers', () => {
    vi.useFakeTimers();
    const store = usePresenceStore.getState();
    store.setTyping('channel', 'user', true);
    vi.advanceTimersByTime(7_000);
    store.setTyping('channel', 'user', true);
    vi.advanceTimersByTime(7_000);
    expect(usePresenceStore.getState().typingUsers.channel.user).toBe(true);
    vi.advanceTimersByTime(1_000);
    expect(usePresenceStore.getState().typingUsers).toEqual({});
    store.setTyping('channel', 'user', true);
    store.clearChannel('channel');
    expect(vi.getTimerCount()).toBe(0);
    expect(usePresenceStore.getState().typingUsers).toEqual({});
  });
});
