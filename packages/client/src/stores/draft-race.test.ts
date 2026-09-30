import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const storage = vi.hoisted(() => ({ save: vi.fn(), remove: vi.fn(), load: vi.fn() }));
vi.mock('../services/local-state.service', () => ({ saveLocalDraft: storage.save, deleteLocalDraft: storage.remove, deleteLocalDraftsForChannel: storage.remove, loadLocalDraft: storage.load }));
import { forumPostDraftScope, useDraftStore } from './draft.store';

beforeEach(() => { vi.useFakeTimers(); useDraftStore.getState().reset(); storage.save.mockReset(); storage.remove.mockReset(); });
afterEach(() => { useDraftStore.getState().reset(); vi.useRealTimers(); });
it('erases an in-flight draft and prevents a stale timer from resurrecting it after revocation', async () => {
  let finish!: () => void;
  const order: string[] = [];
  storage.save.mockImplementation(() => new Promise<void>((resolve) => { finish = () => { order.push('saved'); resolve(); }; }));
  storage.remove.mockImplementation(async () => { order.push('deleted'); });
  const draft = useDraftStore.getState();
  draft.setDraft('channel', 'secret');
  await vi.advanceTimersByTimeAsync(300);
  const clearing = draft.clearChannel('channel');
  draft.setDraft('channel', 'late editor callback');
  await vi.advanceTimersByTimeAsync(300);
  finish();
  await clearing;
  expect(order).toEqual(['saved', 'deleted']);
  expect(useDraftStore.getState().drafts.channel).toBeUndefined();
  await draft.restoreChannel('channel');
  draft.setDraft('channel', 'authorized again');
  expect(useDraftStore.getState().drafts.channel).toBe('authorized again');
});

it('erases forum post drafts with their channel, after any save already running', async () => {
  let finish!: () => void;
  const order: string[] = [];
  const postScope = forumPostDraftScope('channel', 'post');
  storage.save.mockImplementation((scope: string) => new Promise<void>((resolve) => { finish = () => { order.push(`saved:${scope}`); resolve(); }; }));
  storage.remove.mockImplementation(async (scope: string) => { order.push(`deleted:${scope}`); });
  const draft = useDraftStore.getState();
  draft.setDraft(postScope, 'reply in progress');
  await vi.advanceTimersByTimeAsync(300);
  const clearing = draft.clearChannel('channel');
  draft.setDraft(postScope, 'late editor callback');
  await vi.advanceTimersByTimeAsync(300);
  finish();
  await clearing;
  expect(order).toEqual([`saved:${postScope}`, 'deleted:channel']);
  expect(useDraftStore.getState().drafts[postScope]).toBeUndefined();
});
