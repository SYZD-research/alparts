import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ForumPostSummary, ForumTag, Message } from '@alparts/shared';
import type { ForumPostBroadcastState } from './forum-model';

const mocks = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(message: string, readonly status: number, readonly code: string | null = null) {
      super(message);
    }
  }
  const messageState = {
    eventsByChannel: {} as Record<string, Message[]>,
    addMessages: vi.fn((channelId: string, events: Message[]) => {
      const existing = messageState.eventsByChannel[channelId] ?? [];
      messageState.eventsByChannel[channelId] = [...existing.filter((event) => !events.some((added) => added.id === event.id)), ...events];
    }),
    applyPinUpdate: vi.fn(),
  };
  return {
    ApiError,
    messageState,
    retention: vi.fn(),
    api: {
      getForumPosts: vi.fn(),
      getForumTags: vi.fn(),
      getForumPost: vi.fn(),
      getForumPostMessages: vi.fn(),
      markForumPostRead: vi.fn(),
      setForumPostLocked: vi.fn(),
      setForumPostResolved: vi.fn(),
      setForumPostTags: vi.fn(),
      setForumPostPinned: vi.fn(),
      createForumTag: vi.fn(),
      updateForumTag: vi.fn(),
      deleteForumTag: vi.fn(),
    },
  };
});

vi.mock('../services/api', () => ({ api: mocks.api, ApiError: mocks.ApiError }));
vi.mock('./auth.store', () => ({ useAuthStore: { getState: () => ({ user: { id: 'viewer' } }) } }));
vi.mock('./message.store', () => ({
  isForumChannel: () => true,
  setForumRetention: mocks.retention,
  useMessageStore: { getState: () => mocks.messageState },
}));

import { useForumStore } from './forum.store';

const A = 'forum-a';
const B = 'forum-b';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function postState(channelId: string, postId: string, overrides: Partial<ForumPostBroadcastState> = {}): ForumPostBroadcastState {
  return {
    postId,
    channelId,
    authorId: 'author',
    createdAt: '2026-01-01T00:00:00.000Z',
    lastActivityAt: '2026-01-01T00:00:00.000Z',
    replyCount: 0,
    locked: false,
    resolved: false,
    tagIds: [],
    isPinned: false,
    ...overrides,
  };
}

function event(channelId: string, id: string, overrides: Partial<Message> = {}): Message {
  return {
    id,
    channelId,
    authorId: 'author',
    type: 'message',
    content: '',
    createdAt: '2026-01-01T00:00:00.000Z',
    postId: null,
    ...overrides,
  } as Message;
}

function summary(channelId: string, postId: string, overrides: Partial<ForumPostBroadcastState> = {}, unread = false): ForumPostSummary {
  const state = postState(channelId, postId, overrides);
  return { state: { ...state, unread }, root: event(channelId, postId, { createdAt: state.createdAt }) } as ForumPostSummary;
}

function page(summaries: ForumPostSummary[]) {
  return { data: summaries, hasMore: false, cursor: null, viewer: { canCreatePosts: true, canReply: true, canManage: true, canAttach: true, canPin: true } };
}

const tag = (channelId: string, id: string): ForumTag => ({ id, channelId, name: id, position: 0 } as ForumTag);

beforeEach(() => {
  useForumStore.getState().reset();
  mocks.messageState.eventsByChannel = {};
  vi.clearAllMocks();
  mocks.api.getForumTags.mockResolvedValue([]);
  mocks.api.markForumPostRead.mockImplementation(async (postId: string) => ({ channelId: A, postId, lastReadActivityAt: '2026-01-01T00:00:00.000Z' }));
});

describe('forum store responses after the channel is cleared (SQ-02)', () => {
  it('does not bring back a post, its events or tags once access was removed', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1')]));
    await useForumStore.getState().loadPosts(A);
    const postPage = deferred<{ data: Message[]; hasMore: boolean; cursor: null }>();
    const tags = deferred<ForumTag[]>();
    mocks.api.getForumPostMessages.mockReturnValue(postPage.promise);
    mocks.api.getForumTags.mockReturnValue(tags.promise);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1')];

    const opening = useForumStore.getState().openPost(A, 'p1');
    const loadingTags = useForumStore.getState().loadTags(A);
    await flush();
    useForumStore.getState().clearChannel(A);
    mocks.messageState.addMessages.mockClear();
    postPage.resolve({ data: [event(A, 'r1', { postId: 'p1' })], hasMore: false, cursor: null });
    tags.resolve([tag(A, 't1')]);
    await Promise.all([opening, loadingTags]);

    expect(useForumStore.getState().channels[A]).toBeUndefined();
    expect(mocks.messageState.addMessages).not.toHaveBeenCalled();
    expect(mocks.api.markForumPostRead).not.toHaveBeenCalled();
  });

  it('does not recreate the channel from a moderation response that arrives afterwards', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1')]));
    await useForumStore.getState().loadPosts(A);
    const locked = deferred<ForumPostBroadcastState>();
    mocks.api.setForumPostLocked.mockReturnValue(locked.promise);
    const locking = useForumStore.getState().setLocked(A, 'p1', true);
    useForumStore.getState().clearChannel(A);
    locked.resolve(postState(A, 'p1', { locked: true }));
    await locking;
    expect(useForumStore.getState().channels[A]).toBeUndefined();
  });
});

describe('deleting the tag that filters the list (SQ-08)', () => {
  it('reloads every post when the filtering tag disappears', async () => {
    mocks.api.getForumTags.mockResolvedValue([tag(A, 't1')]);
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p2')]));
    await useForumStore.getState().loadPosts(A);
    await useForumStore.getState().loadTags(A);
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1', { tagIds: ['t1'] })]));
    useForumStore.getState().setTagFilter(A, 't1');
    await flush();
    expect(useForumStore.getState().channels[A]?.postIds).toEqual(['p1']);

    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p2')]));
    useForumStore.getState().applyTags(A, []);
    await flush();

    const view = useForumStore.getState().channels[A]!;
    expect(view.tagId).toBeNull();
    expect(mocks.api.getForumPosts).toHaveBeenLastCalledWith(A, { sort: 'activity' });
    expect(view.postIds).toEqual(['p1', 'p2']);
  });
});

describe('an old post whose events left the channel window (SQ-12)', () => {
  it('fetches the post again when its first message is no longer in memory', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'old')]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [];
    mocks.api.getForumPost.mockResolvedValue(summary(A, 'old'));
    mocks.api.getForumPostMessages.mockResolvedValue({ data: [], hasMore: false, cursor: null });

    await useForumStore.getState().openPost(A, 'old');

    expect(mocks.api.getForumPost).toHaveBeenCalledWith('old');
    expect(mocks.messageState.eventsByChannel[A]?.some((candidate) => candidate.id === 'old')).toBe(true);
  });

  it('asks the message store to keep listed and open posts before adding their events', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p2')]));
    await useForumStore.getState().loadPosts(A);
    const [channelId, retained] = mocks.retention.mock.calls[0] as [string, { rootIds: Set<string> }];
    expect(channelId).toBe(A);
    expect([...retained.rootIds].sort()).toEqual(['p1', 'p2']);
    expect(mocks.retention.mock.invocationCallOrder[0]).toBeLessThan(mocks.messageState.addMessages.mock.invocationCallOrder[0]);
  });
});

describe('list responses that started before live updates (SQ-13)', () => {
  it('keeps the newer state, removal and read time', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p2'), summary(A, 'p3')]));
    await useForumStore.getState().loadPosts(A);
    const list = deferred<ReturnType<typeof page>>();
    mocks.api.getForumPosts.mockReturnValue(list.promise);
    const loading = useForumStore.getState().loadPosts(A);

    useForumStore.getState().applyPostState(postState(A, 'p1', { locked: true }));
    useForumStore.getState().removePost(A, 'p2');
    useForumStore.getState().applyPostRead(A, 'p3', '2026-01-02T00:00:00.000Z');
    list.resolve(page([
      summary(A, 'p1'),
      summary(A, 'p2'),
      summary(A, 'p3', { lastActivityAt: '2026-01-02T00:00:00.000Z' }, true),
    ]));
    await loading;

    const view = useForumStore.getState().channels[A]!;
    expect(view.states.p1?.locked).toBe(true);
    expect(view.postIds).not.toContain('p2');
    expect(view.states.p2).toBeUndefined();
    expect(view.lastReadAt.p3).toBe('2026-01-02T00:00:00.000Z');
  });
});

describe('opening a post that fails to load (SQ-17)', () => {
  it('keeps the post and offers a retry when the failure is temporary', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1')]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1')];
    mocks.api.getForumPostMessages.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    await useForumStore.getState().openPost(A, 'p1');
    let view = useForumStore.getState().channels[A]!;
    expect(view.activePostGone).toBe(false);
    expect(view.activePostFailed).toBe(true);

    mocks.api.getForumPostMessages.mockRejectedValueOnce(new mocks.ApiError('busy', 503));
    await useForumStore.getState().openPost(A, 'p1');
    expect(useForumStore.getState().channels[A]!.activePostGone).toBe(false);

    mocks.api.getForumPostMessages.mockResolvedValueOnce({ data: [], hasMore: false, cursor: null });
    await useForumStore.getState().openPost(A, 'p1');
    view = useForumStore.getState().channels[A]!;
    expect(view.activePostFailed).toBe(false);
    expect(view.activePostGone).toBe(false);
  });

  it('shows the post as gone when it was deleted or access was removed', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1')]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1')];
    mocks.api.getForumPostMessages.mockRejectedValueOnce(new mocks.ApiError('missing', 404));
    await useForumStore.getState().openPost(A, 'p1');
    expect(useForumStore.getState().channels[A]!.activePostGone).toBe(true);

    mocks.api.getForumPostMessages.mockRejectedValueOnce(new mocks.ApiError('forbidden', 403));
    await useForumStore.getState().openPost(A, 'p1');
    expect(useForumStore.getState().channels[A]!.activePostGone).toBe(true);
  });
});

describe('tag changes are bound to their forum (SQ-20)', () => {
  it('does not delete or rename a tag of another forum', async () => {
    mocks.api.getForumTags.mockImplementation(async (channelId: string) => [tag(channelId, `${channelId}-tag`)]);
    await useForumStore.getState().loadTags(A);
    await useForumStore.getState().loadTags(B);

    await expect(useForumStore.getState().deleteTag(B, `${A}-tag`)).rejects.toThrow();
    await expect(useForumStore.getState().renameTag(B, `${A}-tag`, 'x')).rejects.toThrow();
    expect(mocks.api.deleteForumTag).not.toHaveBeenCalled();
    expect(mocks.api.updateForumTag).not.toHaveBeenCalled();

    await useForumStore.getState().deleteTag(A, `${A}-tag`);
    expect(mocks.api.deleteForumTag).toHaveBeenCalledWith(`${A}-tag`);
  });
});

describe('reconnecting while a forum is shown (SQ-25)', () => {
  it('reloads the list, the tags and the open post', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1')]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1')];
    mocks.api.getForumPostMessages.mockResolvedValue({ data: [], hasMore: false, cursor: null });
    await useForumStore.getState().openPost(A, 'p1');
    vi.clearAllMocks();
    mocks.api.getForumTags.mockResolvedValue([tag(A, 'new-tag')]);
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p-new')]));
    mocks.api.getForumPost.mockResolvedValue(summary(A, 'p1', { replyCount: 3 }));
    mocks.api.getForumPostMessages.mockResolvedValue({ data: [], hasMore: false, cursor: null });
    mocks.api.markForumPostRead.mockResolvedValue({ channelId: A, postId: 'p1', lastReadActivityAt: '2026-01-01T00:00:00.000Z' });

    await useForumStore.getState().refreshChannel(A);

    const view = useForumStore.getState().channels[A]!;
    expect(view.postIds).toEqual(['p1', 'p-new']);
    expect(view.tags.map((candidate) => candidate.id)).toEqual(['new-tag']);
    expect(view.states.p1?.replyCount).toBe(3);
    expect(mocks.api.getForumPostMessages).toHaveBeenCalledWith('p1');
  });

  it('does nothing for a forum that is not loaded', async () => {
    await useForumStore.getState().refreshChannel(B);
    expect(mocks.api.getForumPosts).not.toHaveBeenCalled();
    expect(useForumStore.getState().channels[B]).toBeUndefined();
  });
});

describe('pinning from the post view (SQ-27)', () => {
  it('updates the button and list order from the response alone', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([
      summary(A, 'newer', { lastActivityAt: '2026-01-03T00:00:00.000Z' }),
      summary(A, 'older', { lastActivityAt: '2026-01-02T00:00:00.000Z' }),
    ]));
    await useForumStore.getState().loadPosts(A);
    mocks.api.setForumPostPinned.mockResolvedValue({
      messageId: 'older', channelId: A, userId: 'viewer', pinned: true,
      forumPost: postState(A, 'older', { lastActivityAt: '2026-01-02T00:00:00.000Z', isPinned: true }),
    });

    await useForumStore.getState().setPinned(A, 'older', true);

    const view = useForumStore.getState().channels[A]!;
    expect(mocks.api.setForumPostPinned).toHaveBeenCalledWith('older', true);
    expect(view.states.older?.isPinned).toBe(true);
    expect(view.postIds).toEqual(['older', 'newer']);
    expect(mocks.messageState.applyPinUpdate).toHaveBeenCalledWith(A, 'older', true);
  });
});

describe('marking a post read (SQ-28)', () => {
  it('does not mark a post read after the viewer left it', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1'), summary(A, 'p2')]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1'), event(A, 'p2')];
    const postPage = deferred<{ data: Message[]; hasMore: boolean; cursor: null }>();
    mocks.api.getForumPostMessages.mockReturnValueOnce(postPage.promise);

    const opening = useForumStore.getState().openPost(A, 'p1');
    await flush();
    await useForumStore.getState().openPost(A, null);
    postPage.resolve({ data: [], hasMore: false, cursor: null });
    await opening;
    await flush();

    expect(mocks.api.markForumPostRead).not.toHaveBeenCalled();
  });

  it('reports only the activity the viewer was shown', async () => {
    mocks.api.getForumPosts.mockResolvedValue(page([summary(A, 'p1', { lastActivityAt: '2026-01-05T00:00:00.000Z' })]));
    await useForumStore.getState().loadPosts(A);
    mocks.messageState.eventsByChannel[A] = [event(A, 'p1')];
    mocks.api.getForumPostMessages.mockResolvedValue({
      data: [event(A, 'r1', { postId: 'p1', createdAt: '2026-01-03T00:00:00.000Z' })],
      hasMore: false,
      cursor: null,
    });

    await useForumStore.getState().openPost(A, 'p1');
    await flush();

    expect(mocks.api.markForumPostRead).toHaveBeenCalledWith('p1', '2026-01-03T00:00:00.000Z');
  });
});
