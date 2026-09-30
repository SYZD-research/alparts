import { describe, expect, it } from 'vitest';
import { forumPostPreview, formatForumTime } from './forum-display';

describe('forum display helpers', () => {
  it('summarizes a Markdown body as plain text', () => {
    expect(forumPostPreview('パスワードで **エラー** が出ます。\n- 再起動済み\n- `cache` 削除済み\n> 引用\n[手順](https://example.test)'))
      .toBe('パスワードで エラー が出ます。 再起動済み cache 削除済み 引用 手順');
    expect([...forumPostPreview('あ'.repeat(500))].length).toBe(200);
  });

  it('formats recent activity relatively', () => {
    const now = Date.parse('2026-10-01T12:00:00.000Z');
    expect(formatForumTime('2026-10-01T11:59:30.000Z', now)).toBe('たった今');
    expect(formatForumTime('2026-10-01T11:00:00.000Z', now)).toBe('1時間前');
    expect(formatForumTime('2026-09-29T12:00:00.000Z', now)).toBe('2日前');
    expect(formatForumTime('invalid', now)).toBe('');
  });
});
