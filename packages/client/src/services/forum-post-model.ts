import { MAX_FORUM_POST_TITLE_LENGTH, MAX_MESSAGE_LENGTH } from '@alparts/shared';

// Formatting controls (including bidirectional overrides) and line breaks
// could make a title look like a different one or break the list layout.
const UNSAFE_TITLE_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export interface ForumPostContent {
  title: string;
  body: string;
}

/** Title as it may be shown: single line, no invisible controls, bounded. */
export function sanitizeForumPostTitle(title: string): string {
  return [...title.normalize('NFC').replace(UNSAFE_TITLE_CHARACTERS, ' ').replace(/\s+/g, ' ').trim()]
    .slice(0, MAX_FORUM_POST_TITLE_LENGTH)
    .join('');
}

/**
 * A post's encrypted text is its title, a line break, then the body. Whether
 * a message is a post is decided by its signed position (a forum message
 * without a post), never by looking at the text.
 */
export function encodeForumPostContent(input: ForumPostContent): string {
  const title = sanitizeForumPostTitle(input.title);
  if (!title) throw new Error('タイトルを入力してください');
  const encoded = `${title}\n${input.body.trim()}`;
  if (encoded.length > MAX_MESSAGE_LENGTH) throw new Error('本文が長すぎます');
  return encoded;
}

export function decodeForumPostContent(content: string): ForumPostContent {
  const lineBreak = content.indexOf('\n');
  const rawTitle = lineBreak === -1 ? content : content.slice(0, lineBreak);
  return {
    title: sanitizeForumPostTitle(rawTitle),
    body: lineBreak === -1 ? '' : content.slice(lineBreak + 1),
  };
}

export function forumPostBodyLimit(title: string): number {
  return Math.max(0, MAX_MESSAGE_LENGTH - sanitizeForumPostTitle(title).length - 1);
}
