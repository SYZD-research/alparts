import { useEffect, useMemo, useState } from 'react';
import { MAX_FORUM_POST_TITLE_LENGTH, type Message } from '@alparts/shared';
import { useForumStore } from '../../stores/forum.store';
import { useMessageStore } from '../../stores/message.store';
import { belongsToPost, getMessageCryptoVerificationState } from '../../stores/message-projector';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { encodeForumPostContent, forumPostBodyLimit } from '../../services/forum-post-model';
import { focusMessageElement } from '../../services/message-navigation';
import { MessageItem } from '../message/MessageItem';
import { MessageInput } from '../message/MessageInput';
import { MessageContent } from '../message/MessageContent';
import { AttachmentItem } from '../message/AttachmentItem';
import { UserAvatar } from '../user/UserAvatar';
import { isPictureHidden } from '../../stores/profile-visibility';
import { Dialog } from '../ui/Dialog';
import { TagPicker } from './ForumView';
import { FORUM_UNREADABLE_DETAIL, forumPostDisplay, formatForumTime } from './forum-display';
import { useT } from '../../i18n';

interface Props {
  channelId: string;
  postId: string;
  sendDisabled: boolean;
}

const EMPTY_MESSAGES: Message[] = [];

export function ForumPostView({ channelId, postId, sendDisabled }: Props) {
  const t = useT();
  const view = useForumStore((state) => state.channels[channelId]);
  const openPost = useForumStore((state) => state.openPost);
  const loadMorePostMessages = useForumStore((state) => state.loadMorePostMessages);
  const setLocked = useForumStore((state) => state.setLocked);
  const setResolved = useForumStore((state) => state.setResolved);
  const setPostTags = useForumStore((state) => state.setPostTags);
  const messages = useMessageStore((state) => state.messagesByChannel[channelId] || EMPTY_MESSAGES);
  const baseRoot = useMessageStore((state) => state.eventsByChannel[channelId]?.find((event) => event.id === postId && event.type === 'message'));
  const editMessage = useMessageStore((state) => state.editMessage);
  const deleteMessage = useMessageStore((state) => state.deleteMessage);
  const setPinned = useForumStore((state) => state.setPinned);
  const toggleReaction = useMessageStore((state) => state.toggleReaction);
  const members = useWorkspaceStore((state) => state.members);
  const warnedUsers = useWorkspaceStore((state) => state.warnedUsers);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const openMemberProfile = useUiStore((state) => state.openMemberProfile);
  const currentUserId = useAuthStore((state) => state.user?.id ?? null);
  const [editing, setEditing] = useState<{ title: string; body: string } | null>(null);
  const [editingTags, setEditingTags] = useState<string[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setEditing(null);
    setEditingTags(null);
    setConfirmDelete(false);
    setActionError(null);
  }, [postId]);

  const root = messages.find((message) => message.id === postId);
  // Replies are the verified events signed for this post. A v5 reply also
  // names the post's first message as its author signed it, so a server that
  // serves another post under this id cannot show the reply under it.
  const replies = useMemo(
    () => (root ? messages.filter((message) => belongsToPost(message, root)) : []),
    [messages, root],
  );
  // A reply is listed once it verifies, so the post is not empty before that.
  const repliesPending = useMemo(
    () => messages.some((message) => message.postId === postId && getMessageCryptoVerificationState(message) === undefined),
    [messages, postId],
  );
  const state = view?.states[postId];
  const display = forumPostDisplay(root);
  const viewer = view?.viewer;
  const isAuthor = Boolean(root && root.authorId === currentUserId);
  const canManage = Boolean(viewer?.canManage);
  const locked = Boolean(state?.locked);
  const canReply = Boolean(viewer?.canReply) && (!locked || canManage);
  const tags = (state?.tagIds ?? []).flatMap((tagId) => view?.tags.find((tag) => tag.id === tagId) ?? []);
  const authorName = root?.author?.displayName || members.find((member) => member.userId === state?.authorId)?.user.displayName || t('不明なユーザー');

  const back = () => void openPost(channelId, null);

  const act = async (operation: () => Promise<unknown>, failure: string) => {
    setBusy(true);
    setActionError(null);
    try {
      await operation();
      return true;
    } catch {
      setActionError(failure);
      return false;
    } finally {
      setBusy(false);
    }
  };

  if (view?.activePostFailed && display.status !== 'ready') {
    return (
      <div role="alert" className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-muted">
        <p>{t('投稿を読み込めませんでした。')}</p>
        <div className="flex gap-2">
          <button type="button" onClick={() => void openPost(channelId, postId)} className="rounded-lg bg-hover px-3 py-2 text-sm text-ink hover:text-ink-strong">{t('再試行')}</button>
          <button type="button" onClick={back} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">{t('投稿一覧へ戻る')}</button>
        </div>
      </div>
    );
  }

  if (view?.activePostGone || display.status === 'deleted') {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-muted">
        <p>{t('この投稿は削除されたか、表示できなくなりました。')}</p>
        <button type="button" onClick={back} className="rounded-lg bg-hover px-3 py-2 text-sm text-ink hover:text-ink-strong">{t('投稿一覧へ戻る')}</button>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-line px-4 py-2">
        <button type="button" onClick={back} className="h-9 rounded-lg px-2 text-sm text-muted hover:bg-hover hover:text-ink-strong">
          {t('← 投稿一覧')}
        </button>
        <div className="ml-auto flex flex-wrap items-center justify-end gap-1">
          {state && (isAuthor || canManage) && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setResolved(channelId, postId, !state.resolved), t('状態を変更できませんでした。'))}
              className="h-9 rounded-lg px-2 text-sm text-muted hover:bg-hover hover:text-ink-strong disabled:opacity-50"
            >
              {state.resolved ? t('未解決に戻す') : t('解決済みにする')}
            </button>
          )}
          {state && (isAuthor || canManage) && view && view.tags.length > 0 && (
            <button type="button" onClick={() => setEditingTags(state.tagIds)} className="h-9 rounded-lg px-2 text-sm text-muted hover:bg-hover hover:text-ink-strong">
              {t('タグを編集')}
            </button>
          )}
          {state && viewer?.canPin && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setPinned(channelId, postId, !state.isPinned), t('ピン留めを変更できませんでした。'))}
              className="h-9 rounded-lg px-2 text-sm text-muted hover:bg-hover hover:text-ink-strong disabled:opacity-50"
            >
              {state.isPinned ? t('ピンを外す') : t('ピン留め')}
            </button>
          )}
          {state && canManage && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setLocked(channelId, postId, !state.locked), t('ロックを変更できませんでした。'))}
              className="h-9 rounded-lg px-2 text-sm text-muted hover:bg-hover hover:text-ink-strong disabled:opacity-50"
            >
              {state.locked ? t('ロックを解除') : t('ロック')}
            </button>
          )}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        <article id={`message-${postId}`} tabIndex={-1} className="rounded-xl border border-line bg-panel/60 px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            {state?.isPinned && <span className="text-xs text-warning">{t('📌 ピン留め')}</span>}
            {state?.resolved && <span className="rounded-md bg-success/15 px-1.5 py-0.5 text-xs font-medium text-success">{t('解決済み')}</span>}
            {locked && <span className="rounded-md bg-hover px-1.5 py-0.5 text-xs text-muted">{t('🔒 ロック中')}</span>}
            {tags.map((tag) => (
              <span key={tag.id} className="rounded-md border border-line px-1.5 py-0.5 text-xs text-ink-soft">{tag.name}</span>
            ))}
          </div>
          {display.status === 'ready' ? (
            editing ? (
              <form
                className="mt-2 space-y-2"
                onSubmit={(event) => {
                  event.preventDefault();
                  let content: string;
                  try {
                    content = encodeForumPostContent(editing);
                  } catch (caught) {
                    setActionError(caught instanceof Error ? caught.message : t('投稿を保存できませんでした。'));
                    return;
                  }
                  void act(() => editMessage(postId, channelId, content), t('投稿を保存できませんでした。'))
                    .then((saved) => { if (saved) setEditing(null); });
                }}
              >
                <input
                  value={editing.title}
                  maxLength={MAX_FORUM_POST_TITLE_LENGTH}
                  onChange={(event) => setEditing({ ...editing, title: event.target.value })}
                  aria-label={t('タイトル')}
                  className="h-10 w-full rounded-lg bg-field px-3 text-ink"
                />
                <textarea
                  value={editing.body}
                  maxLength={forumPostBodyLimit(editing.title)}
                  onChange={(event) => setEditing({ ...editing, body: event.target.value })}
                  aria-label={t('本文')}
                  rows={6}
                  className="w-full resize-y rounded-lg bg-field px-3 py-2 text-ink"
                />
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={() => setEditing(null)} className="rounded-lg px-3 py-1 text-sm text-muted hover:bg-hover">{t('キャンセル')}</button>
                  <button type="submit" disabled={busy || sendDisabled || !editing.title.trim()} className="rounded-lg bg-accent px-3 py-1 text-sm text-on-accent disabled:opacity-50">{t('保存')}</button>
                </div>
              </form>
            ) : (
              <>
                <h2 className="mt-1 wrap-break-word text-xl font-semibold text-ink-strong">{display.title}</h2>
                <div className="mt-2 flex items-center gap-2 text-sm text-muted">
                  {root && (
                    <UserAvatar
                      displayName={authorName}
                      avatarUrl={root.author?.avatarUrl}
                      hidden={isPictureHidden(root.authorId, members, warnedUsers)}
                      size="sm"
                    />
                  )}
                  <button
                    type="button"
                    onClick={() => { if (activeWorkspaceId && root) openMemberProfile(activeWorkspaceId, root.authorId); }}
                    className="font-semibold text-ink hover:underline"
                  >
                    {authorName}
                  </button>
                  {root && <time dateTime={root.createdAt}>{formatForumTime(root.createdAt)}</time>}
                  {display.edited && <span className="text-xs">{t('（編集済み）')}</span>}
                </div>
                {display.body && (
                  <div className="message-markdown mt-3 wrap-break-word text-ink">
                    <MessageContent content={display.body} members={members} currentUserId={currentUserId} authenticatedBroadcastMention={root?.broadcastMention === true} />
                  </div>
                )}
                {root?.attachments?.map((attachment) => (
                  <AttachmentItem key={attachment.id} attachment={attachment} message={baseRoot || root} />
                ))}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {(root?.reactions ?? []).map((reaction) => (
                    <button
                      key={reaction.emoji}
                      type="button"
                      onClick={() => { if (currentUserId) void toggleReaction(postId, reaction.emoji, channelId, currentUserId).catch(() => undefined); }}
                      className={`flex h-7 items-center rounded-full border px-2.5 text-sm transition-colors ${currentUserId && reaction.userIds.includes(currentUserId) ? 'border-accent/45 bg-accent/10 text-accent' : 'border-line bg-panel/60 text-ink-soft hover:border-line-strong hover:bg-hover'}`}
                    >
                      {reaction.emoji} {reaction.count}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => { if (currentUserId) void toggleReaction(postId, '👍', channelId, currentUserId).catch(() => undefined); }}
                    className="flex h-7 items-center rounded-full border border-dashed border-line px-2.5 text-sm text-muted transition-colors hover:border-line-strong hover:bg-hover"
                    aria-label={t('いいね')}
                  >
                    👍
                  </button>
                  {isAuthor && (
                    <button type="button" onClick={() => setEditing({ title: display.title, body: display.body })} className="ml-auto text-sm text-muted underline">{t('編集')}</button>
                  )}
                  {(isAuthor || canManage) && (
                    <button type="button" onClick={() => setConfirmDelete(true)} className={`${isAuthor ? '' : 'ml-auto '}text-sm text-danger underline`}>{t('削除')}</button>
                  )}
                </div>
              </>
            )
          ) : (
            <p className="mt-2 text-muted">
              {display.status === 'loading'
                ? t('読み込み中…')
                : display.status === 'unreadable' ? t(FORUM_UNREADABLE_DETAIL) : t('この投稿は安全性を確認できないため表示できません。')}
            </p>
          )}
        </article>

        {view?.activePostFailed && (
          <div role="alert" className="mt-2 flex items-center justify-between gap-3 rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">
            <span>{t('返信を読み込めませんでした。')}</span>
            <button type="button" onClick={() => void openPost(channelId, postId)} className="underline">{t('再試行')}</button>
          </div>
        )}

        {actionError && (
          <div role="alert" className="mt-2 flex items-center justify-between gap-3 rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">
            <span>{actionError}</span>
            <button type="button" onClick={() => setActionError(null)} className="underline">{t('閉じる')}</button>
          </div>
        )}

        <h3 className="mb-1 mt-4 text-sm font-semibold text-muted">{t('返信 {count}件', { count: state ? state.replyCount : replies.filter((reply) => reply.type !== 'delete').length })}</h3>
        {view?.postHasMore[postId] && (
          <div className="py-2 text-center">
            <button
              type="button"
              disabled={view.postLoading[postId]}
              onClick={() => void loadMorePostMessages(channelId, postId)}
              className="rounded-lg bg-hover px-3 py-1 text-sm text-ink hover:text-ink-strong disabled:opacity-50"
            >
              {view.postLoading[postId] ? t('読み込み中…') : t('以前の返信を表示')}
            </button>
          </div>
        )}
        {replies.length === 0 && !view?.postLoading[postId] && !repliesPending && (
          <p className="px-4 py-3 text-sm text-muted">{t('まだ返信はありません。')}</p>
        )}
        {replies.map((message, index) => {
          const previous = replies[index - 1];
          const isFirst = !previous
            || previous.authorId !== message.authorId
            || Boolean(message.refMessageId)
            || new Date(message.createdAt).getTime() - new Date(previous.createdAt).getTime() > 5 * 60 * 1000;
          return (
            <MessageItem
              key={message.id}
              message={message}
              isFirst={isFirst}
              canPin={false}
              onJumpToMessage={(messageId) => { void focusMessageElement(messageId); }}
            />
          );
        })}
      </div>

      {canReply ? (
        // Keyed by post so files and pasted text chosen in one post never reach another.
        <MessageInput key={postId} channelId={channelId} postId={postId} sendDisabled={sendDisabled} placeholder={t('返信を送信')} />
      ) : (
        <p role="status" className="border-t border-line px-4 py-3 text-sm text-muted">
          {locked ? t('この投稿はロックされているため、返信できません。') : t('このフォーラムに返信する権限がありません。')}
        </p>
      )}

      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title={t('投稿を削除しますか？')} size="sm">
        <div className="space-y-4">
          <p className="rounded-lg border border-danger/60 bg-danger/10 p-3 text-sm text-ink">
            {t('投稿を削除すると、返信も表示されなくなり、新しく返信できなくなります。この操作は元に戻せません。')}
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmDelete(false)} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">{t('キャンセル')}</button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => deleteMessage(postId, channelId), t('投稿を削除できませんでした。')).then((deleted) => {
                setConfirmDelete(false);
                if (deleted) back();
              })}
              className="rounded-lg bg-danger px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {t('削除')}
            </button>
          </div>
        </div>
      </Dialog>

      <Dialog open={editingTags !== null} onClose={() => setEditingTags(null)} title={t('タグを編集')} size="sm">
        <div className="space-y-4">
          <TagPicker tags={view?.tags ?? []} selected={editingTags ?? []} onChange={setEditingTags} />
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setEditingTags(null)} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">{t('キャンセル')}</button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setPostTags(channelId, postId, editingTags ?? []), t('タグを保存できませんでした。')).then((saved) => {
                if (saved) setEditingTags(null);
              })}
              className="rounded-lg bg-accent px-3 py-2 text-sm font-medium text-on-accent disabled:opacity-50"
            >
              {t('保存')}
            </button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
