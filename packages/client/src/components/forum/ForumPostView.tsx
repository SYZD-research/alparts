import { useEffect, useMemo, useState } from 'react';
import { MAX_FORUM_POST_TITLE_LENGTH, type Message } from '@alparts/shared';
import { useForumStore } from '../../stores/forum.store';
import { useMessageStore } from '../../stores/message.store';
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
import { forumPostDisplay, formatForumTime } from './forum-display';

interface Props {
  channelId: string;
  postId: string;
  sendDisabled: boolean;
}

const EMPTY_MESSAGES: Message[] = [];

export function ForumPostView({ channelId, postId, sendDisabled }: Props) {
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
  const pinMessage = useMessageStore((state) => state.pinMessage);
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
  // Replies are the verified events signed for this post; the signature binds
  // them to it, so the server cannot move a reply into another post.
  const replies = useMemo(
    () => messages.filter((message) => message.postId === postId && message.type !== 'reaction'),
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
  const authorName = root?.author?.displayName || members.find((member) => member.userId === state?.authorId)?.user.displayName || '不明なユーザー';

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

  if (view?.activePostGone || display.status === 'deleted') {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center text-discord-muted">
        <p>この投稿は削除されたか、表示できなくなりました。</p>
        <button type="button" onClick={back} className="rounded bg-discord-hover px-3 py-2 text-sm text-discord-text hover:text-white">投稿一覧へ戻る</button>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-discord-sidebar px-4 py-2">
        <button type="button" onClick={back} className="h-9 rounded px-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white">
          ← 投稿一覧
        </button>
        <div className="ml-auto flex flex-wrap items-center justify-end gap-1">
          {state && (isAuthor || canManage) && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setResolved(channelId, postId, !state.resolved), '状態を変更できませんでした。')}
              className="h-9 rounded px-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50"
            >
              {state.resolved ? '未解決に戻す' : '解決済みにする'}
            </button>
          )}
          {state && (isAuthor || canManage) && view && view.tags.length > 0 && (
            <button type="button" onClick={() => setEditingTags(state.tagIds)} className="h-9 rounded px-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white">
              タグを編集
            </button>
          )}
          {state && viewer?.canPin && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => pinMessage(postId, channelId), 'ピン留めを変更できませんでした。')}
              className="h-9 rounded px-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50"
            >
              {state.isPinned ? 'ピンを外す' : 'ピン留め'}
            </button>
          )}
          {state && canManage && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setLocked(channelId, postId, !state.locked), 'ロックを変更できませんでした。')}
              className="h-9 rounded px-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50"
            >
              {state.locked ? 'ロックを解除' : 'ロック'}
            </button>
          )}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        <article id={`message-${postId}`} tabIndex={-1} className="rounded border border-discord-hover bg-discord-sidebar/60 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            {state?.isPinned && <span className="text-xs text-discord-yellow">📌 ピン留め</span>}
            {state?.resolved && <span className="rounded bg-discord-green/20 px-1.5 text-xs text-discord-green">解決済み</span>}
            {locked && <span className="rounded bg-discord-hover px-1.5 text-xs text-discord-muted">🔒 ロック中</span>}
            {tags.map((tag) => (
              <span key={tag.id} className="rounded bg-discord-input px-1.5 py-0.5 text-xs text-discord-text">{tag.name}</span>
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
                    setActionError(caught instanceof Error ? caught.message : '投稿を保存できませんでした。');
                    return;
                  }
                  void act(() => editMessage(postId, channelId, content), '投稿を保存できませんでした。')
                    .then((saved) => { if (saved) setEditing(null); });
                }}
              >
                <input
                  value={editing.title}
                  maxLength={MAX_FORUM_POST_TITLE_LENGTH}
                  onChange={(event) => setEditing({ ...editing, title: event.target.value })}
                  aria-label="タイトル"
                  className="h-10 w-full rounded bg-discord-input px-3 text-discord-text"
                />
                <textarea
                  value={editing.body}
                  maxLength={forumPostBodyLimit(editing.title)}
                  onChange={(event) => setEditing({ ...editing, body: event.target.value })}
                  aria-label="本文"
                  rows={6}
                  className="w-full resize-y rounded bg-discord-input px-3 py-2 text-discord-text"
                />
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={() => setEditing(null)} className="rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover">キャンセル</button>
                  <button type="submit" disabled={busy || sendDisabled || !editing.title.trim()} className="rounded bg-discord-accent px-3 py-1 text-sm text-white disabled:opacity-50">保存</button>
                </div>
              </form>
            ) : (
              <>
                <h2 className="mt-1 break-words text-xl font-bold text-white">{display.title}</h2>
                <div className="mt-2 flex items-center gap-2 text-sm text-discord-muted">
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
                    className="font-medium text-discord-text hover:underline"
                  >
                    {authorName}
                  </button>
                  {root && <time dateTime={root.createdAt}>{formatForumTime(root.createdAt)}</time>}
                  {display.edited && <span className="text-xs">（編集済み）</span>}
                </div>
                {display.body && (
                  <div className="mt-3 break-words text-discord-text">
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
                      className={`rounded px-2 py-0.5 text-sm ${currentUserId && reaction.userIds.includes(currentUserId) ? 'bg-discord-accent/30 text-white' : 'bg-discord-input text-discord-text'}`}
                    >
                      {reaction.emoji} {reaction.count}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => { if (currentUserId) void toggleReaction(postId, '👍', channelId, currentUserId).catch(() => undefined); }}
                    className="rounded px-2 py-0.5 text-sm text-discord-muted hover:bg-discord-hover"
                    aria-label="いいね"
                  >
                    👍
                  </button>
                  {isAuthor && (
                    <button type="button" onClick={() => setEditing({ title: display.title, body: display.body })} className="ml-auto text-sm text-discord-muted underline">編集</button>
                  )}
                  {(isAuthor || canManage) && (
                    <button type="button" onClick={() => setConfirmDelete(true)} className={`${isAuthor ? '' : 'ml-auto '}text-sm text-discord-red underline`}>削除</button>
                  )}
                </div>
              </>
            )
          ) : (
            <p className="mt-2 text-discord-muted">{display.status === 'loading' ? '読み込み中…' : 'この投稿を表示できません'}</p>
          )}
        </article>

        {actionError && (
          <div role="alert" className="mt-2 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
            <span>{actionError}</span>
            <button type="button" onClick={() => setActionError(null)} className="underline">閉じる</button>
          </div>
        )}

        <h3 className="mb-1 mt-4 text-sm font-semibold text-discord-muted">返信 {state ? state.replyCount : replies.filter((reply) => reply.type !== 'delete').length}件</h3>
        {view?.postHasMore[postId] && (
          <div className="py-2 text-center">
            <button
              type="button"
              disabled={view.postLoading[postId]}
              onClick={() => void loadMorePostMessages(channelId, postId)}
              className="rounded bg-discord-hover px-3 py-1 text-sm text-discord-text hover:text-white disabled:opacity-50"
            >
              {view.postLoading[postId] ? '読み込み中…' : '以前の返信を表示'}
            </button>
          </div>
        )}
        {replies.length === 0 && !view?.postLoading[postId] && (
          <p className="px-4 py-3 text-sm text-discord-muted">まだ返信はありません。</p>
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
        <MessageInput channelId={channelId} postId={postId} sendDisabled={sendDisabled} placeholder="返信を送信" />
      ) : (
        <p role="status" className="border-t border-discord-sidebar px-4 py-3 text-sm text-discord-muted">
          {locked ? 'この投稿はロックされているため、返信できません。' : 'このフォーラムに返信する権限がありません。'}
        </p>
      )}

      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title="投稿を削除しますか？" size="sm">
        <div className="space-y-4">
          <p className="rounded border border-discord-red/60 bg-discord-red/10 p-3 text-sm text-discord-text">
            投稿を削除すると、返信も表示されなくなり、新しく返信できなくなります。この操作は元に戻せません。
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmDelete(false)} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">キャンセル</button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => deleteMessage(postId, channelId), '投稿を削除できませんでした。').then((deleted) => {
                setConfirmDelete(false);
                if (deleted) back();
              })}
              className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              削除
            </button>
          </div>
        </div>
      </Dialog>

      <Dialog open={editingTags !== null} onClose={() => setEditingTags(null)} title="タグを編集" size="sm">
        <div className="space-y-4">
          <TagPicker tags={view?.tags ?? []} selected={editingTags ?? []} onChange={setEditingTags} />
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setEditingTags(null)} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">キャンセル</button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => setPostTags(channelId, postId, editingTags ?? []), 'タグを保存できませんでした。').then((saved) => {
                if (saved) setEditingTags(null);
              })}
              className="rounded bg-discord-accent px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              保存
            </button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
