import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const storage = vi.hoisted(() => ({ save: vi.fn(), remove: vi.fn(), load: vi.fn() }));
vi.mock('../services/local-state.service', () => ({ saveLocalDraft: storage.save, deleteLocalDraft: storage.remove, loadLocalDraft: storage.load }));
import { useDraftStore } from './draft.store';

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
