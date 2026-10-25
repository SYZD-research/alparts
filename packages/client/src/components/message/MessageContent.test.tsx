import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { WorkspaceMember } from '@alparts/shared';
import { MessageContent } from './MessageContent';

const members: WorkspaceMember[] = [
  member('00000000-0000-4000-8000-000000000001', 'Alice'),
  member('00000000-0000-4000-8000-000000000002', 'Bob'),
];

describe('MessageContent', () => {
  it('makes hyperlinks visually explicit and distinguishes own and other mentions', () => {
    const html = renderToStaticMarkup(
      <MessageContent
        content={'@Alice @Bob https://example.com'}
        members={members}
        currentUserId={members[0].userId}
      />,
    );

    expect(html).toContain('data-mention-self="true"');
    expect(html).toContain('text-orange-300');
    expect(html).toContain('data-mention-user-id="00000000-0000-4000-8000-000000000002"');
    expect(html).toContain('text-sky-400');
    expect(html).toContain('href="https://example.com"');
    expect(html).toContain('↗');
  });

  it('names the host a link opens beside its text, and keeps the whole address in the tooltip', () => {
    const html = renderContent('Please re-verify: [click here](https://evil.example/phish?a=1&b=2)');

    expect(html).toContain('href="https://evil.example/phish?a=1&amp;b=2"');
    expect(html).toContain('>click here<');
    expect(html).toMatch(/<span class="[^"]*">evil\.example<\/span>/);
    expect(html).toContain('title="リンク先: https://evil.example/phish?a=1&amp;b=2"');
    expect(html).not.toContain('<button');
  });

  it('leaves plain autolinks as they were', () => {
    for (const content of ['https://example.com/a?b=c', 'www.example.com/path', '<https://example.com>', 'person@example.com']) {
      const html = renderContent(content);
      expect(html, content).toContain('title="新しいタブでリンクを開く"');
      expect(html, content).toContain('↗</span></a>');
      expect(html, content).not.toContain('<button');
      expect(html, content).not.toContain('bg-hover');
    }
  });

  it('asks before opening a link whose text names another site', () => {
    const html = renderContent('Please re-verify: [https://accounts.example.com/verify](https://evil.example/phish)');

    // No address of its own: a click cannot be turned into a middle-click or a new window that skips the question.
    expect(html).toContain('<button type="button"');
    expect(html).not.toContain('<a ');
    expect(html).not.toContain('href=');
    expect(html).toContain('>https://accounts.example.com/verify<');
    expect(html).toMatch(/<span class="[^"]*">evil\.example<\/span>/);
    expect(html).toContain('title="リンク先: https://evil.example/phish"');
    // Nothing is asked until the link is chosen.
    expect(html).not.toContain('role="dialog"');
  });

  it('asks in the same way when the text is formatted or is only a host name', () => {
    for (const content of [
      '[accounts.example.com](https://evil.example/)',
      '[**https://accounts.example.com**](https://evil.example/)',
      '[`accounts.example.com`](https://evil.example/)',
      '[www.example.com/login](https://evil.example/)',
      '[Open https://accounts.example.com/verify now](https://evil.example/)',
      '[![https://accounts.example.com](x.png)](https://evil.example/)',
    ]) {
      expect(renderContent(content), content).toContain('<button type="button"');
    }
  });

  it('does not ask about ordinary link text, but still names the host', () => {
    for (const content of ['[the docs](https://github.com/org/repo)', '[README.md](https://github.com/org/repo)', '[こちら](https://github.com/org/repo)']) {
      const html = renderContent(content);
      expect(html, content).toContain('href="https://github.com/org/repo"');
      expect(html, content).toMatch(/<span class="[^"]*">github\.com<\/span>/);
      expect(html, content).not.toContain('<button');
    }
  });

  it('never shows a title the author wrote for the link', () => {
    const html = renderContent('[docs](https://evil.example/ "https://accounts.example.com")');
    expect(html).toContain('title="リンク先: https://evil.example/"');
    expect(html).not.toContain('title="https://accounts.example.com"');
  });

  it('leaves unsafe addresses and links within the app as they were', () => {
    expect(renderContent('[x](javascript:alert(1))')).toContain('title="このリンクは開けません"');
    const inApp = renderContent('[https://accounts.example.com](/help)');
    expect(inApp).toContain('href="/help"');
    expect(inApp).toContain('title="新しいタブでリンクを開く"');
    expect(inApp).not.toContain('<button');
  });

  it('renders canonical mention ids as display names and leaves code untouched', () => {
    const html = renderToStaticMarkup(
      <MessageContent
        content={'<@00000000-0000-4000-8000-000000000001> `@Alice`'}
        members={members}
        currentUserId={members[0].userId}
      />,
    );

    expect(html).toContain('data-mention-self="true"');
    expect(html).toContain('<code>@Alice</code>');
  });

  it('replaces internal message markers with a plain safety notice', () => {
    const html = renderToStaticMarkup(
      <MessageContent
        content="[改ざんを検出しました]"
        members={members}
        currentUserId={members[0].userId}
      />,
    );

    expect(html).toContain('安全性を確認できないため、このメッセージを表示できません');
    expect(html).not.toContain('改ざん');
  });
});

function renderContent(content: string): string {
  return renderToStaticMarkup(<MessageContent content={content} members={members} currentUserId={null} />);
}

function member(userId: string, displayName: string): WorkspaceMember {
  return {
    id: `membership-${userId}`,
    workspaceId: '00000000-0000-4000-8000-000000000003',
    userId,
    user: {
      id: userId,
      displayName,
      avatarUrl: null,
      status: 'online',
      createdAt: '2026-09-03T00:00:00.000Z',
    },
    roles: [],
    joinedAt: '2026-09-03T00:00:00.000Z',
  };
}
