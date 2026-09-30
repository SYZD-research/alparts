import type { Message } from '@alparts/shared';
import { getMessageCryptoVerificationState } from '../../stores/message-projector';
import { decodeForumPostContent } from '../../services/forum-post-model';

export type ForumPostDisplay =
  | { status: 'loading' }
  | { status: 'unavailable' }
  | { status: 'deleted' }
  | { status: 'ready'; title: string; body: string; edited: boolean };

/**
 * What to show for a post, from its projected root message. Only a verified
 * root that really starts a post (no post of its own) is read as title + body.
 */
export function forumPostDisplay(root: Message | undefined): ForumPostDisplay {
  if (!root) return { status: 'loading' };
  if (root.type === 'delete') return { status: 'deleted' };
  if (root.postId) return { status: 'unavailable' };
  const verified = getMessageCryptoVerificationState(root);
  if (verified === undefined) return { status: 'loading' };
  if (verified !== true) return { status: 'unavailable' };
  const { title, body } = decodeForumPostContent(root.content);
  return { status: 'ready', title: title || '無題の投稿', body, edited: root.type === 'edit' };
}

export function formatForumTime(value: string, now = Date.now()): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return '';
  const minutes = Math.floor((now - time) / 60_000);
  if (minutes < 1) return 'たった今';
  if (minutes < 60) return `${minutes}分前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}時間前`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}日前`;
  return new Date(time).toLocaleDateString('ja-JP');
}
