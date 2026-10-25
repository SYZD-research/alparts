import { useEffect, useMemo, useState } from 'react';
import {
  MAX_FILE_SIZE,
  MAX_FORUM_POST_TITLE_LENGTH,
  MAX_FORUM_TAG_NAME_LENGTH,
  MAX_FORUM_TAGS_PER_CHANNEL,
  MAX_FORUM_TAGS_PER_POST,
  type ForumTag,
  type Message,
} from '@alparts/shared';
import { useForumStore, type ForumChannelView } from '../../stores/forum.store';
import { useMessageStore } from '../../stores/message.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { useAttachmentStore } from '../../stores/attachment.store';
import { useUserStateStore } from '../../stores/user-state.store';
import { latestReadableMessageId } from '../../stores/user-state-model';
import { isForumPostUnread, type ForumPostBroadcastState } from '../../stores/forum-model';
import { forumPostBodyLimit } from '../../services/forum-post-model';
import { extractMentionedUserIds } from '../../services/mention-model';
import { ATTACHMENT_MAX_COUNT_PER_MESSAGE } from '../../services/attachment-crypto.service';
import { ApiError } from '../../services/api';
import { sendWithAttachments, type HeldAttachments } from '../../services/attachment-send-model';
import { Dialog } from '../ui/Dialog';
import { ForumPostView } from './ForumPostView';
import { FORUM_UNREADABLE_TITLE, forumPostDisplay, forumPostPreview, formatForumTime } from './forum-display';
import { Icon } from '../ui/Icon';
import { useT } from '../../i18n';

interface Props {
  channelId: string;
  sendDisabled: boolean;
  visible?: boolean;
}

const EMPTY_MESSAGES: Message[] = [];

export function ForumView({ channelId, sendDisabled, visible = true }: Props) {
  const forum = useForumStore((state) => state.channels[channelId]);
  useMarkForumChannelRead(channelId, visible);
  const loadPosts = useForumStore((state) => state.loadPosts);
  const loadTags = useForumStore((state) => state.loadTags);
  const authorizationRefreshVersion = useUiStore((state) => state.authorizationRefreshVersion);
  const [composerOpen, setComposerOpen] = useState(false);
  const [tagManagerOpen, setTagManagerOpen] = useState(false);

  useEffect(() => {
    void loadPosts(channelId);
    void loadTags(channelId);
  }, [authorizationRefreshVersion, channelId, loadPosts, loadTags]);

  useEffect(() => {
    setComposerOpen(false);
    setTagManagerOpen(false);
  }, [channelId]);

  const view = forum;
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {view?.activePostId ? (
        <ForumPostView channelId={channelId} postId={view.activePostId} sendDisabled={sendDisabled} />
      ) : (
        <ForumPostList
          channelId={channelId}
          view={view}
          onCreate={() => setComposerOpen(true)}
          onManageTags={() => setTagManagerOpen(true)}
        />
      )}
      {/* Keyed by forum so a draft or a pending deletion never carries over to another forum.
          The keys differ because sibling keys must be unique. */}
      {view && (
        <ForumPostComposer
          key={`composer:${channelId}`}
          open={composerOpen}
          channelId={channelId}
          tags={view.tags}
          canAttach={Boolean(view.viewer?.canAttach)}
          sendDisabled={sendDisabled}
          onClose={() => setComposerOpen(false)}
        />
      )}
      {view && (
        <ForumTagManager
          key={`tags:${channelId}`}
          open={tagManagerOpen}
          channelId={channelId}
          tags={view.tags}
          onClose={() => setTagManagerOpen(false)}
        />
      )}
    </div>
  );
}

/**
 * Looking at a forum clears the channel's unread count in the sidebar, like
 * reading a chat does. Each post keeps its own new-reply marker.
 */
function useMarkForumChannelRead(channelId: string, visible: boolean) {
  const messages = useMessageStore((state) => state.messagesByChannel[channelId] || EMPTY_MESSAGES);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const lastReadMessageId = useUserStateStore((state) => activeWorkspaceId
    ? state.channelStatesByWorkspace[activeWorkspaceId]?.[channelId]?.lastReadMessageId || null
    : null);
  const channelStateReady = useUserStateStore((state) => Boolean(
    activeWorkspaceId && state.channelStatesByWorkspace[activeWorkspaceId]?.[channelId],
  ));
  const markRead = useUserStateStore((state) => state.markRead);
  const latest = useMemo(() => latestReadableMessageId(messages), [messages]);

  useEffect(() => {
    if (!visible || !channelStateReady || !latest || latest === lastReadMessageId) return;
    const mark = () => {
      if (document.visibilityState === 'visible' && document.hasFocus()) void markRead(channelId, latest);
    };
    mark();
    window.addEventListener('focus', mark);
    document.addEventListener('visibilitychange', mark);
    return () => {
      window.removeEventListener('focus', mark);
      document.removeEventListener('visibilitychange', mark);
    };
  }, [channelId, channelStateReady, lastReadMessageId, latest, markRead, visible]);
}

function ForumPostList({ channelId, view, onCreate, onManageTags }: {
  channelId: string;
  view: ForumChannelView | undefined;
  onCreate: () => void;
  onManageTags: () => void;
}) {
  const t = useT();
  const messages = useMessageStore((state) => state.messagesByChannel[channelId] || EMPTY_MESSAGES);
  const members = useWorkspaceStore((state) => state.members);
  const currentUserId = useAuthStore((state) => state.user?.id ?? null);
  const setSort = useForumStore((state) => state.setSort);
  const setTagFilter = useForumStore((state) => state.setTagFilter);
  const openPost = useForumStore((state) => state.openPost);
  const loadMorePosts = useForumStore((state) => state.loadMorePosts);
  const loadPosts = useForumStore((state) => state.loadPosts);
  const [query, setQuery] = useState('');

  const messagesById = useMemo(() => new Map(messages.map((message) => [message.id, message])), [messages]);
  const tagsById = useMemo(() => new Map((view?.tags ?? []).map((tag) => [tag.id, tag])), [view?.tags]);
  const normalizedQuery = query.trim().normalize('NFKC').toLocaleLowerCase();
  const rows = (view?.postIds ?? []).flatMap((postId) => {
    const state = view?.states[postId];
    if (!state) return [];
    const display = forumPostDisplay(messagesById.get(postId));
    if (normalizedQuery) {
      if (display.status !== 'ready') return [];
      const haystack = `${display.title}\n${display.body}`.normalize('NFKC').toLocaleLowerCase();
      if (!haystack.includes(normalizedQuery)) return [];
    }
    return [{ state, display }];
  });

  if (!view || (!view.loaded && view.loading)) {
    return <div className="flex flex-1 items-center justify-center text-muted">{t('読み込み中…')}</div>;
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        {view.viewer?.canCreatePosts && (
          <button type="button" onClick={onCreate} className="flex h-9 items-center gap-1.5 rounded-lg bg-accent px-3.5 text-sm font-medium text-on-accent transition-colors hover:bg-accent-strong">
            <Icon name="plus" size={16} />
            {t('新しい投稿')}
          </button>
        )}
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t('投稿を検索')}
          aria-label={t('表示中の投稿を検索')}
          className="h-9 min-w-0 flex-1 rounded-lg bg-field px-3 text-sm text-ink placeholder:text-muted"
        />
        <select
          value={view.sort}
          onChange={(event) => setSort(channelId, event.target.value === 'created' ? 'created' : 'activity')}
          aria-label={t('並び順')}
          className="h-9 rounded-lg bg-field px-2 text-sm text-ink"
        >
          <option value="activity">{t('最新の返信順')}</option>
          <option value="created">{t('新しい投稿順')}</option>
        </select>
        {view.viewer?.canManage && (
          <button type="button" onClick={onManageTags} className="h-9 rounded-lg px-3 text-sm text-muted hover:bg-hover hover:text-ink-strong">
            {t('タグを管理')}
          </button>
        )}
      </div>
      {view.tags.length > 0 && (
        <div className="flex flex-wrap gap-2 px-4 pt-3" role="group" aria-label={t('タグで絞り込み')}>
          <FilterChip active={!view.tagId} onClick={() => setTagFilter(channelId, null)}>{t('すべて|filter')}</FilterChip>
          {view.tags.map((tag) => (
            <FilterChip key={tag.id} active={view.tagId === tag.id} onClick={() => setTagFilter(channelId, tag.id)}>
              {tag.name}
            </FilterChip>
          ))}
        </div>
      )}
      {view.error && (
        <div role="alert" className="mx-4 mt-3 flex items-center justify-between gap-3 rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">
          <span>{t('投稿を読み込めませんでした。')}</span>
          <button type="button" onClick={() => void loadPosts(channelId)} className="underline">{t('再試行')}</button>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {rows.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-muted">
            {normalizedQuery ? (
              <p>{t('表示中の投稿に一致するものはありません。')}</p>
            ) : (
              <>
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-line bg-raised text-ink-soft">
                  <Icon name="forum" size={28} />
                </div>
                <p className="text-lg font-semibold text-ink-strong">{t('まだ投稿はありません')}</p>
                {view.viewer?.canCreatePosts && (
                  <button type="button" onClick={onCreate} className="rounded-lg bg-accent px-3 py-2 text-sm text-on-accent hover:bg-accent-strong">
                    {t('最初の投稿を作成')}
                  </button>
                )}
              </>
            )}
          </div>
        ) : (
          <ul className="space-y-2">
            {rows.map(({ state, display }) => (
              <li key={state.postId}>
                <ForumPostRow
                  state={state}
                  display={display}
                  tags={state.tagIds.flatMap((tagId) => tagsById.get(tagId) ?? [])}
                  authorName={members.find((member) => member.userId === state.authorId)?.user.displayName || messagesById.get(state.postId)?.author?.displayName || t('不明なユーザー')}
                  unread={isForumPostUnread(state, view.lastReadAt[state.postId], currentUserId)}
                  onOpen={() => void openPost(channelId, state.postId)}
                />
              </li>
            ))}
          </ul>
        )}
        {view.hasMore && (
          <div className="py-3 text-center">
            <button
              type="button"
              disabled={view.loadingMore}
              onClick={() => void loadMorePosts(channelId)}
              className="rounded-lg bg-hover px-3 py-2 text-sm text-ink hover:text-ink-strong disabled:opacity-50"
            >
              {view.loadingMore ? t('読み込み中…') : t('さらに表示')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function ForumPostRow({ state, display, tags, authorName, unread, onOpen }: {
  state: ForumPostBroadcastState;
  display: ReturnType<typeof forumPostDisplay>;
  tags: ForumTag[];
  authorName: string;
  unread: boolean;
  onOpen: () => void;
}) {
  const t = useT();
  const title = display.status === 'ready'
    ? display.title
    : display.status === 'loading'
      ? t('読み込み中…')
      : display.status === 'unreadable' ? t(FORUM_UNREADABLE_TITLE) : t('この投稿を表示できません');
  return (
    <button
      type="button"
      onClick={onOpen}
      className="w-full rounded-xl border border-line bg-panel/60 px-4 py-3.5 text-left transition-colors hover:border-line-strong hover:bg-hover/50"
    >
      <div className="flex flex-wrap items-center gap-2">
        {state.isPinned && <span className="text-xs text-warning">{t('📌 ピン留め')}</span>}
        {state.resolved && <span className="rounded-md bg-success/15 px-1.5 py-0.5 text-xs font-medium text-success">{t('解決済み')}</span>}
        {state.locked && <span className="rounded-md bg-hover px-1.5 py-0.5 text-xs text-muted">{t('🔒 ロック中')}</span>}
        {unread && <span className="rounded-md bg-accent px-1.5 py-0.5 text-xs font-medium text-on-accent">{t('新着')}</span>}
      </div>
      <p className={`mt-1 wrap-break-word text-base ${unread ? 'font-semibold text-ink-strong' : 'font-medium text-ink'}`}>{title}</p>
      {display.status === 'ready' && display.body && (
        <p className="mt-1 line-clamp-2 wrap-break-word text-sm text-muted">{forumPostPreview(display.body)}</p>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
        <span>{authorName}</span>
        <span className="sr-only">{t('返信 {count}件', { count: state.replyCount })}</span>
        <span aria-hidden="true" className="flex items-center gap-1"><Icon name="forum" size={13} />{state.replyCount}</span>
        <span>{formatForumTime(state.lastActivityAt)}</span>
        {tags.map((tag) => (
          <span key={tag.id} className="rounded-md border border-line px-1.5 py-0.5 text-ink-soft">{tag.name}</span>
        ))}
      </div>
    </button>
  );
}

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-sm transition-colors ${active ? 'border-transparent bg-accent text-on-accent' : 'border-line text-ink-soft hover:bg-hover hover:text-ink-strong'}`}
    >
      {children}
    </button>
  );
}

export function TagPicker({ tags, selected, onChange }: {
  tags: ForumTag[];
  selected: string[];
  onChange: (tagIds: string[]) => void;
}) {
  const t = useT();
  if (tags.length === 0) return null;
  return (
    <fieldset>
      <legend className="mb-1 text-sm font-medium text-ink">{t('タグ（{count}個まで）', { count: MAX_FORUM_TAGS_PER_POST })}</legend>
      <div className="flex flex-wrap gap-2">
        {tags.map((tag) => {
          const checked = selected.includes(tag.id);
          const disabled = !checked && selected.length >= MAX_FORUM_TAGS_PER_POST;
          return (
            <label key={tag.id} className={`flex items-center gap-1 rounded-full border px-3 py-1 text-sm ${checked ? 'border-transparent bg-accent text-on-accent' : 'border-line text-ink-soft'} ${disabled ? 'opacity-50' : 'cursor-pointer'}`}>
              <input
                type="checkbox"
                className="sr-only"
                checked={checked}
                disabled={disabled}
                onChange={() => onChange(checked ? selected.filter((id) => id !== tag.id) : [...selected, tag.id])}
              />
              {tag.name}
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

function ForumPostComposer({ open, channelId, tags, canAttach, sendDisabled, onClose }: {
  open: boolean;
  channelId: string;
  tags: ForumTag[];
  canAttach: boolean;
  sendDisabled: boolean;
  onClose: () => void;
}) {
  const t = useT();
  const createPost = useForumStore((state) => state.createPost);
  const openPost = useForumStore((state) => state.openPost);
  const startUploads = useAttachmentStore((state) => state.startUploads);
  const members = useWorkspaceStore((state) => state.members);
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [tagIds, setTagIds] = useState<string[]>([]);
  const [files, setFiles] = useState<File[]>([]);
  // A post that was created while its files could not be queued yet.
  const [held, setHeld] = useState<HeldAttachments | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setError(null);
  }, [open]);

  const close = () => {
    if (submitting) return;
    if (held) {
      // The post exists already; leaving shows it without the files.
      const postId = held.message.id;
      setHeld(null);
      setTitle('');
      setBody('');
      setTagIds([]);
      setFiles([]);
      onClose();
      void openPost(channelId, postId);
      return;
    }
    onClose();
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting || sendDisabled) return;
    if (!title.trim()) {
      setError(t('タイトルを入力してください。'));
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const mentionedUserIds = extractMentionedUserIds(body, members.map((member) => ({
        userId: member.userId,
        displayName: member.user.displayName,
      })));
      const create = () => createPost(channelId, { title, body, tagIds, mentionedUserIds });
      let message: Message;
      if (files.length > 0) {
        const result = await sendWithAttachments(held, files, create, startUploads);
        if (result.status === 'held') {
          setHeld(result.held);
          setError(t('投稿は作成しましたが、ファイルを送信できませんでした。もう一度お試しください。'));
          return;
        }
        void result.uploads.catch(() => undefined);
        message = result.message;
      } else {
        message = held?.message ?? await create();
      }
      setHeld(null);
      setTitle('');
      setBody('');
      setTagIds([]);
      setFiles([]);
      onClose();
      void openPost(channelId, message.id);
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 403
        ? t('このフォーラムに投稿する権限がありません。')
        : t('投稿を作成できませんでした。もう一度お試しください。'));
    } finally {
      setSubmitting(false);
    }
  };

  const addFiles = (selected: File[]) => {
    const next = [...files, ...selected];
    if (next.length > ATTACHMENT_MAX_COUNT_PER_MESSAGE) {
      setError(t('添付ファイルは{count}件までです。', { count: ATTACHMENT_MAX_COUNT_PER_MESSAGE }));
      return;
    }
    const oversized = next.find((file) => file.size > MAX_FILE_SIZE);
    if (oversized) {
      setError(t('{name} は100MBを超えています。', { name: oversized.name }));
      return;
    }
    setError(null);
    setFiles(next);
  };

  return (
    <Dialog open={open} onClose={close} title={t('新しい投稿')} size="md">
      <form className="space-y-4" onSubmit={(event) => void submit(event)}>
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-ink">{t('タイトル')}</span>
          <input
            value={title}
            disabled={held !== null}
            maxLength={MAX_FORUM_POST_TITLE_LENGTH}
            onChange={(event) => setTitle(event.target.value)}
            className="h-10 w-full rounded-lg bg-field px-3 text-ink"
            autoFocus
            required
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-ink">{t('本文')}</span>
          <textarea
            value={body}
            disabled={held !== null}
            maxLength={forumPostBodyLimit(title)}
            onChange={(event) => setBody(event.target.value)}
            rows={8}
            className="w-full resize-y rounded-lg bg-field px-3 py-2 text-ink"
          />
        </label>
        <TagPicker tags={tags} selected={tagIds} onChange={setTagIds} />
        {canAttach && (
          <div>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg bg-hover px-3 py-2 text-sm text-ink hover:text-ink-strong">
              {t('ファイルを追加')}
              <input
                type="file"
                multiple
                className="sr-only"
                onChange={(event) => {
                  addFiles(Array.from(event.target.files || []));
                  event.target.value = '';
                }}
              />
            </label>
            {files.length > 0 && (
              <ul className="mt-2 space-y-1 text-sm text-muted">
                {files.map((file, index) => (
                  <li key={`${file.name}-${index}`} className="flex items-center justify-between gap-2">
                    <span className="truncate">{file.name}</span>
                    <button type="button" onClick={() => setFiles(files.filter((_, i) => i !== index))} className="underline">{t('削除')}</button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        {sendDisabled && <p role="status" className="text-sm text-warning">{t('送信の準備ができるまでお待ちください。')}</p>}
        {error && <p role="alert" className="rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={close} disabled={submitting} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover disabled:opacity-50">
            {t('キャンセル')}
          </button>
          <button type="submit" disabled={submitting || sendDisabled || !title.trim()} className="rounded-lg bg-accent px-3 py-2 text-sm font-medium text-on-accent disabled:opacity-50">
            {submitting ? t('投稿中…') : held ? t('ファイルを再送信') : t('投稿する')}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function ForumTagManager({ open, channelId, tags, onClose }: {
  open: boolean;
  channelId: string;
  tags: ForumTag[];
  onClose: () => void;
}) {
  const t = useT();
  const createTag = useForumStore((state) => state.createTag);
  const renameTag = useForumStore((state) => state.renameTag);
  const deleteTag = useForumStore((state) => state.deleteTag);
  const [name, setName] = useState('');
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ForumTag | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (operation: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 409
        ? t('同じ名前のタグがあるか、タグの上限に達しています。')
        : caught instanceof ApiError && caught.status === 400
          ? t('タグ名に使用できない文字が含まれています。')
          : t('タグを保存できませんでした。もう一度お試しください。'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title={t('タグを管理')} description={t('タグ名は投稿の内容と違い、サーバーの管理者も見ることができます。人に知られたくない内容はタグ名に含めないでください。')} size="sm">
      <div className="space-y-4">
        <form
          className="flex gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const trimmed = name.trim();
            if (!trimmed) return;
            void run(async () => {
              await createTag(channelId, trimmed);
              setName('');
            });
          }}
        >
          <input
            value={name}
            maxLength={MAX_FORUM_TAG_NAME_LENGTH}
            onChange={(event) => setName(event.target.value)}
            placeholder={t('新しいタグ')}
            aria-label={t('新しいタグ名')}
            disabled={tags.length >= MAX_FORUM_TAGS_PER_CHANNEL}
            className="h-9 min-w-0 flex-1 rounded-lg bg-field px-3 text-sm text-ink"
          />
          <button type="submit" disabled={busy || !name.trim() || tags.length >= MAX_FORUM_TAGS_PER_CHANNEL} className="rounded-lg bg-accent px-3 text-sm text-on-accent disabled:opacity-50">
            {t('追加')}
          </button>
        </form>
        {tags.length >= MAX_FORUM_TAGS_PER_CHANNEL && (
          <p className="text-sm text-muted">{t('タグは{count}個まで作成できます。', { count: MAX_FORUM_TAGS_PER_CHANNEL })}</p>
        )}
        {error && <p role="alert" className="rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">{error}</p>}
        <ul className="space-y-2">
          {tags.map((tag) => (
            <li key={tag.id} className="flex items-center gap-2">
              {editing?.id === tag.id ? (
                <form
                  className="flex flex-1 gap-2"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const trimmed = editing.name.trim();
                    if (!trimmed) return;
                    void run(async () => {
                      await renameTag(channelId, tag.id, trimmed);
                      setEditing(null);
                    });
                  }}
                >
                  <input
                    value={editing.name}
                    maxLength={MAX_FORUM_TAG_NAME_LENGTH}
                    onChange={(event) => setEditing({ id: tag.id, name: event.target.value })}
                    aria-label={t('タグ名')}
                    className="h-8 min-w-0 flex-1 rounded-lg bg-field px-2 text-sm text-ink"
                    autoFocus
                  />
                  <button type="submit" disabled={busy} className="text-sm text-accent underline">{t('保存')}</button>
                  <button type="button" onClick={() => setEditing(null)} className="text-sm text-muted underline">{t('キャンセル')}</button>
                </form>
              ) : (
                <>
                  <span className="flex-1 truncate rounded-lg bg-field px-2 py-1 text-sm text-ink">{tag.name}</span>
                  <button type="button" onClick={() => setEditing({ id: tag.id, name: tag.name })} className="text-sm text-muted underline">{t('名前を変更')}</button>
                  <button type="button" onClick={() => setConfirmDelete(tag)} className="text-sm text-danger underline">{t('削除')}</button>
                </>
              )}
            </li>
          ))}
        </ul>
        {confirmDelete && (
          <div role="alertdialog" aria-label={t('タグの削除')} className="space-y-2 rounded-lg border border-danger/60 bg-danger/10 p-3 text-sm text-ink">
            <p>{t('「{name}」を削除すると、このタグはすべての投稿から外れます。', { name: confirmDelete.name })}</p>
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setConfirmDelete(null)} className="rounded-lg px-3 py-1 text-muted hover:bg-hover">{t('キャンセル')}</button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void run(async () => {
                  await deleteTag(channelId, confirmDelete.id);
                  setConfirmDelete(null);
                })}
                className="rounded-lg bg-danger px-3 py-1 text-white disabled:opacity-50"
              >
                {t('削除')}
              </button>
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}
