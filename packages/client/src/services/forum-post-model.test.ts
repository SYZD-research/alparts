import { describe, expect, it } from 'vitest';
import { MAX_FORUM_POST_TITLE_LENGTH, MAX_MESSAGE_LENGTH } from '@alparts/shared';
import {
  decodeForumPostContent,
  encodeForumPostContent,
  forumPostBodyLimit,
  sanitizeForumPostTitle,
} from './forum-post-model';

describe('forum post content', () => {
  it('round-trips a title and a multi-line body', () => {
    const encoded = encodeForumPostContent({ title: '  ログインできない ', body: '手順:\n1. 開く\n2. 失敗\n' });
    expect(encoded).toBe('ログインできない\n手順:\n1. 開く\n2. 失敗');
    expect(decodeForumPostContent(encoded)).toEqual({ title: 'ログインできない', body: '手順:\n1. 開く\n2. 失敗' });
  });

  it('removes invisible and direction-changing characters from titles', () => {
    expect(sanitizeForumPostTitle('invoice‮txt.exe')).toBe('invoice txt.exe');
    expect(sanitizeForumPostTitle('a​b\tc\r\nd')).toBe('a b c d');
    expect(decodeForumPostContent('⁦title⁩\nbody').title).toBe('title');
  });

  it('bounds the title and rejects empty or oversized posts', () => {
    expect([...sanitizeForumPostTitle('あ'.repeat(500))].length).toBe(MAX_FORUM_POST_TITLE_LENGTH);
    expect(() => encodeForumPostContent({ title: ' ​ ', body: 'x' })).toThrow();
    expect(() => encodeForumPostContent({ title: 't', body: 'x'.repeat(MAX_MESSAGE_LENGTH) })).toThrow();
    expect(forumPostBodyLimit('t')).toBe(MAX_MESSAGE_LENGTH - 2);
  });

  it('treats text without a line break as a title only', () => {
    expect(decodeForumPostContent('only title')).toEqual({ title: 'only title', body: '' });
  });
});
