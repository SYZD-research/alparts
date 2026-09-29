import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { MemberProfile } from '@alparts/shared';
import { MemberProfileView } from './MemberProfileDialog';

const profile = (overrides: Partial<MemberProfile> = {}): MemberProfile => ({
  userId: '00000000-0000-4000-8000-000000000001',
  displayName: 'Mallory',
  avatarUrl: '/api/users/00000000-0000-4000-8000-000000000001/avatar/00000000-0000-4000-8000-000000000002',
  bio: 'visit https://phishing.example to verify your account',
  flagged: false,
  canManageFlag: false,
  ...overrides,
});

const render = (value: MemberProfile, revealed: boolean) => renderToStaticMarkup(
  <MemberProfileView
    profile={value}
    revealed={revealed}
    busy={false}
    error={null}
    target={{ workspaceId: '00000000-0000-4000-8000-000000000009', userId: value.userId }}
    act={async () => undefined}
    onReveal={() => undefined}
    onClose={() => undefined}
  />,
);

describe('member profile warning', () => {
  it('shows only the confirmation for a warned profile until the viewer chooses to see it', () => {
    const html = render(profile({ flagged: true }), false);
    expect(html).toContain('<strong>なりすまし・及び悪質なサービスへの誘導</strong>');
    expect(html).toContain('それでも見ますか？');
    expect(html).not.toContain('phishing.example');
    expect(html).not.toContain('<img');
  });

  it('shows the self-introduction as plain text after confirmation, with a reminder', () => {
    const html = render(profile({ flagged: true, bio: '<b>hi</b>\nline two' }), true);
    expect(html).toContain('&lt;b&gt;hi&lt;/b&gt;');
    expect(html).toContain('警告を付けています');
  });

  it('shows an unwarned profile directly and offers the warning only to managers', () => {
    expect(render(profile(), false)).toContain('phishing.example');
    expect(render(profile(), false)).not.toContain('警告を付ける');
    expect(render(profile({ canManageFlag: true }), false)).toContain('警告を付ける');
  });
});
