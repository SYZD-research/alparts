import type { Message } from '@alparts/shared';
import { getMessageCryptoVerificationState, isMessageKeyUnavailable } from '../../stores/message-projector';
import { decodeForumPostContent } from '../../services/forum-post-model';
import { intlLocale, msg, t } from '../../i18n';

export type ForumPostDisplay =
  | { status: 'loading' }
  | { status: 'unavailable' }
  /** This device has no key for it, e.g. it was written before the viewer joined. */
  | { status: 'unreadable' }
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
  if (isMessageKeyUnavailable(root)) return { status: 'unreadable' };
  if (verified !== true) return { status: 'unavailable' };
  const { title, body } = decodeForumPostContent(root.content);
  return { status: 'ready', title: title || t('無題の投稿'), body, edited: root.type === 'edit' };
}

export const FORUM_UNREADABLE_TITLE = msg('この端末では読めない投稿');
export const FORUM_UNREADABLE_DETAIL = msg('この投稿の内容は、この端末では表示できません。フォーラムに参加する前に作成された投稿は表示されません。');

export function formatForumTime(value: string, now = Date.now()): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return '';
  const minutes = Math.floor((now - time) / 60_000);
  if (minutes < 1) return t('たった今');
  if (minutes < 60) return t('{count}分前', { count: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t('{count}時間前', { count: hours });
  const days = Math.floor(hours / 24);
  if (days < 7) return t('{count}日前', { count: days });
  return new Date(time).toLocaleDateString(intlLocale());
}

/** A short plain-text summary of a Markdown body for the post list. */
export function forumPostPreview(body: string, maxLength = 200): string {
  const text = body
    .split('\n')
    .map((line) => line
      .replace(/^\s{0,3}(?:#{1,6}\s+|>\s?|[-*+]\s+|\d+[.)]\s+)/, '')
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/(\*\*|__|~~|`)/g, '')
      .trim())
    .filter(Boolean)
    .join(' ');
  return [...text].slice(0, maxLength).join('');
}
