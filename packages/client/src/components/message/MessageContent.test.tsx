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
