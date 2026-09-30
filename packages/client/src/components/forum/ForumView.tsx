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
import { isForumPostUnread, type ForumPostBroadcastState } from '../../stores/forum-model';
import { forumPostBodyLimit } from '../../services/forum-post-model';
import { extractMentionedUserIds } from '../../services/mention-model';
import { ATTACHMENT_MAX_COUNT_PER_MESSAGE } from '../../services/attachment-crypto.service';
import { ApiError } from '../../services/api';
import { Dialog } from '../ui/Dialog';
import { ForumPostView } from './ForumPostView';
import { forumPostDisplay, formatForumTime } from './forum-display';

interface Props {
  channelId: string;
  sendDisabled: boolean;
}

const EMPTY_MESSAGES: Message[] = [];

export function ForumView({ channelId, sendDisabled }: Props) {
  const forum = useForumStore((state) => state.channels[channelId]);
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
      {view && (
        <ForumPostComposer
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
          open={tagManagerOpen}
          channelId={channelId}
          tags={view.tags}
          onClose={() => setTagManagerOpen(false)}
        />
      )}
    </div>
  );
}

function ForumPostList({ channelId, view, onCreate, onManageTags }: {
  channelId: string;
  view: ForumChannelView | undefined;
  onCreate: () => void;
  onManageTags: () => void;
}) {
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
    return <div className="flex flex-1 items-center justify-center text-discord-muted">読み込み中...</div>;
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-discord-sidebar px-4 py-3">
        {view.viewer?.canCreatePosts && (
          <button type="button" onClick={onCreate} className="h-9 rounded bg-discord-accent px-3 text-sm font-medium text-white hover:bg-discord-accent-hover">
            新しい投稿
          </button>
        )}
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="投稿を検索"
          aria-label="表示中の投稿を検索"
          className="h-9 min-w-0 flex-1 rounded bg-discord-input px-3 text-sm text-discord-text placeholder:text-discord-muted"
        />
        <select
          value={view.sort}
          onChange={(event) => setSort(channelId, event.target.value === 'created' ? 'created' : 'activity')}
          aria-label="並び順"
          className="h-9 rounded bg-discord-input px-2 text-sm text-discord-text"
        >
          <option value="activity">最新の返信順</option>
          <option value="created">新しい投稿順</option>
        </select>
        {view.viewer?.canManage && (
          <button type="button" onClick={onManageTags} className="h-9 rounded px-3 text-sm text-discord-muted hover:bg-discord-hover hover:text-white">
            タグを管理
          </button>
        )}
      </div>
      {view.tags.length > 0 && (
        <div className="flex flex-wrap gap-2 px-4 pt-3" role="group" aria-label="タグで絞り込み">
          <FilterChip active={!view.tagId} onClick={() => setTagFilter(channelId, null)}>すべて</FilterChip>
          {view.tags.map((tag) => (
            <FilterChip key={tag.id} active={view.tagId === tag.id} onClick={() => setTagFilter(channelId, tag.id)}>
              {tag.name}
            </FilterChip>
          ))}
        </div>
      )}
      {view.error && (
        <div role="alert" className="mx-4 mt-3 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
          <span>投稿を読み込めませんでした。</span>
          <button type="button" onClick={() => void loadPosts(channelId)} className="underline">再試行</button>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {rows.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-discord-muted">
            {normalizedQuery ? (
              <p>表示中の投稿に一致するものはありません。</p>
            ) : (
              <>
                <p className="text-lg font-bold text-discord-text">まだ投稿はありません</p>
                {view.viewer?.canCreatePosts && (
                  <button type="button" onClick={onCreate} className="rounded bg-discord-accent px-3 py-2 text-sm text-white hover:bg-discord-accent-hover">
                    最初の投稿を作成
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
                  authorName={members.find((member) => member.userId === state.authorId)?.user.displayName || messagesById.get(state.postId)?.author?.displayName || '不明なユーザー'}
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
              className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white disabled:opacity-50"
            >
              {view.loadingMore ? '読み込み中…' : 'さらに表示'}
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
  const title = display.status === 'ready'
    ? display.title
    : display.status === 'loading' ? '読み込み中…' : 'この投稿を表示できません';
  return (
    <button
      type="button"
      onClick={onOpen}
      className="w-full rounded border border-discord-hover bg-discord-sidebar/60 px-4 py-3 text-left hover:bg-discord-hover/60"
    >
      <div className="flex flex-wrap items-center gap-2">
        {state.isPinned && <span className="text-xs text-discord-yellow">📌 ピン留め</span>}
        {state.resolved && <span className="rounded bg-discord-green/20 px-1.5 text-xs text-discord-green">解決済み</span>}
        {state.locked && <span className="rounded bg-discord-hover px-1.5 text-xs text-discord-muted">🔒 ロック中</span>}
        {unread && <span className="rounded bg-discord-accent px-1.5 text-xs font-medium text-white">新着</span>}
      </div>
      <p className={`mt-1 break-words text-base ${unread ? 'font-bold text-white' : 'font-medium text-discord-text'}`}>{title}</p>
      {display.status === 'ready' && display.body && (
        <p className="mt-1 line-clamp-2 whitespace-pre-wrap break-words text-sm text-discord-muted">{display.body}</p>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-discord-muted">
        <span>{authorName}</span>
        <span>💬 {state.replyCount}</span>
        <span>{formatForumTime(state.lastActivityAt)}</span>
        {tags.map((tag) => (
          <span key={tag.id} className="rounded bg-discord-input px-1.5 py-0.5 text-discord-text">{tag.name}</span>
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
      className={`rounded-full px-3 py-1 text-sm ${active ? 'bg-discord-accent text-white' : 'bg-discord-input text-discord-text hover:bg-discord-hover'}`}
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
  if (tags.length === 0) return null;
  return (
    <fieldset>
      <legend className="mb-1 text-sm font-medium text-discord-text">タグ（{MAX_FORUM_TAGS_PER_POST}個まで）</legend>
      <div className="flex flex-wrap gap-2">
        {tags.map((tag) => {
          const checked = selected.includes(tag.id);
          const disabled = !checked && selected.length >= MAX_FORUM_TAGS_PER_POST;
          return (
            <label key={tag.id} className={`flex items-center gap-1 rounded-full px-3 py-1 text-sm ${checked ? 'bg-discord-accent text-white' : 'bg-discord-input text-discord-text'} ${disabled ? 'opacity-50' : 'cursor-pointer'}`}>
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
  const createPost = useForumStore((state) => state.createPost);
  const openPost = useForumStore((state) => state.openPost);
  const startUploads = useAttachmentStore((state) => state.startUploads);
  const members = useWorkspaceStore((state) => state.members);
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [tagIds, setTagIds] = useState<string[]>([]);
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setError(null);
  }, [open]);

  const close = () => {
    if (submitting) return;
    onClose();
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting || sendDisabled) return;
    if (!title.trim()) {
      setError('タイトルを入力してください。');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const mentionedUserIds = extractMentionedUserIds(body, members.map((member) => ({
        userId: member.userId,
        displayName: member.user.displayName,
      })));
      const message = await createPost(channelId, { title, body, tagIds, mentionedUserIds });
      if (files.length > 0) {
        void startUploads(message, files).catch(() => undefined);
      }
      setTitle('');
      setBody('');
      setTagIds([]);
      setFiles([]);
      onClose();
      void openPost(channelId, message.id);
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 403
        ? 'このフォーラムに投稿する権限がありません。'
        : '投稿を作成できませんでした。もう一度お試しください。');
    } finally {
      setSubmitting(false);
    }
  };

  const addFiles = (selected: File[]) => {
    const next = [...files, ...selected];
    if (next.length > ATTACHMENT_MAX_COUNT_PER_MESSAGE) {
      setError(`添付ファイルは${ATTACHMENT_MAX_COUNT_PER_MESSAGE}件までです。`);
      return;
    }
    const oversized = next.find((file) => file.size > MAX_FILE_SIZE);
    if (oversized) {
      setError(`${oversized.name} は100MBを超えています。`);
      return;
    }
    setError(null);
    setFiles(next);
  };

  return (
    <Dialog open={open} onClose={close} title="新しい投稿" size="md">
      <form className="space-y-4" onSubmit={(event) => void submit(event)}>
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-discord-text">タイトル</span>
          <input
            value={title}
            maxLength={MAX_FORUM_POST_TITLE_LENGTH}
            onChange={(event) => setTitle(event.target.value)}
            className="h-10 w-full rounded bg-discord-input px-3 text-discord-text"
            autoFocus
            required
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-discord-text">本文</span>
          <textarea
            value={body}
            maxLength={forumPostBodyLimit(title)}
            onChange={(event) => setBody(event.target.value)}
            rows={8}
            className="w-full resize-y rounded bg-discord-input px-3 py-2 text-discord-text"
          />
        </label>
        <TagPicker tags={tags} selected={tagIds} onChange={setTagIds} />
        {canAttach && (
          <div>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white">
              ファイルを追加
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
              <ul className="mt-2 space-y-1 text-sm text-discord-muted">
                {files.map((file, index) => (
                  <li key={`${file.name}-${index}`} className="flex items-center justify-between gap-2">
                    <span className="truncate">{file.name}</span>
                    <button type="button" onClick={() => setFiles(files.filter((_, i) => i !== index))} className="underline">削除</button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        {sendDisabled && <p role="status" className="text-sm text-discord-yellow">送信の準備ができるまでお待ちください。</p>}
        {error && <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={close} disabled={submitting} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">
            キャンセル
          </button>
          <button type="submit" disabled={submitting || sendDisabled || !title.trim()} className="rounded bg-discord-accent px-3 py-2 text-sm font-medium text-white disabled:opacity-50">
            {submitting ? '投稿中…' : '投稿する'}
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
        ? '同じ名前のタグがあるか、タグの上限に達しています。'
        : caught instanceof ApiError && caught.status === 400
          ? 'タグ名に使用できない文字が含まれています。'
          : 'タグを保存できませんでした。もう一度お試しください。');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title="タグを管理" description="タグ名は投稿の内容と違い、サーバーの管理者も見ることができます。人に知られたくない内容はタグ名に含めないでください。" size="sm">
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
            placeholder="新しいタグ"
            aria-label="新しいタグ名"
            disabled={tags.length >= MAX_FORUM_TAGS_PER_CHANNEL}
            className="h-9 min-w-0 flex-1 rounded bg-discord-input px-3 text-sm text-discord-text"
          />
          <button type="submit" disabled={busy || !name.trim() || tags.length >= MAX_FORUM_TAGS_PER_CHANNEL} className="rounded bg-discord-accent px-3 text-sm text-white disabled:opacity-50">
            追加
          </button>
        </form>
        {tags.length >= MAX_FORUM_TAGS_PER_CHANNEL && (
          <p className="text-sm text-discord-muted">タグは{MAX_FORUM_TAGS_PER_CHANNEL}個まで作成できます。</p>
        )}
        {error && <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{error}</p>}
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
                    aria-label="タグ名"
                    className="h-8 min-w-0 flex-1 rounded bg-discord-input px-2 text-sm text-discord-text"
                    autoFocus
                  />
                  <button type="submit" disabled={busy} className="text-sm text-discord-accent underline">保存</button>
                  <button type="button" onClick={() => setEditing(null)} className="text-sm text-discord-muted underline">キャンセル</button>
                </form>
              ) : (
                <>
                  <span className="flex-1 truncate rounded bg-discord-input px-2 py-1 text-sm text-discord-text">{tag.name}</span>
                  <button type="button" onClick={() => setEditing({ id: tag.id, name: tag.name })} className="text-sm text-discord-muted underline">名前を変更</button>
                  <button type="button" onClick={() => setConfirmDelete(tag)} className="text-sm text-discord-red underline">削除</button>
                </>
              )}
            </li>
          ))}
        </ul>
        {confirmDelete && (
          <div role="alertdialog" aria-label="タグの削除" className="space-y-2 rounded border border-discord-red/60 bg-discord-red/10 p-3 text-sm text-discord-text">
            <p>「{confirmDelete.name}」を削除すると、このタグはすべての投稿から外れます。</p>
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setConfirmDelete(null)} className="rounded px-3 py-1 text-discord-muted hover:bg-discord-hover">キャンセル</button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void run(async () => {
                  await deleteTag(channelId, confirmDelete.id);
                  setConfirmDelete(null);
                })}
                className="rounded bg-discord-red px-3 py-1 text-white disabled:opacity-50"
              >
                削除
              </button>
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}
