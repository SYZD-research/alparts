import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { NewRecoveryCode } from './HistoryRecoverySettings';

const code = '0123abcd-4567ef01-89abcdef-01234567-89abcdef-01234567-89abcdef-01234567';
const render = (passkeyProtected: boolean) => renderToStaticMarkup(
  <NewRecoveryCode
    plan={{ code, passkeyProtected }}
    busy={false}
    onEnable={() => undefined}
    onCancel={() => undefined}
  />,
);

describe('new recovery code', () => {
  it('warns before restore is turned on that only the code can restore history', () => {
    const html = render(false);
    expect(html).toContain(code);
    expect(html).toContain('保存済みの履歴は、復旧コードでのみ復元できます。コードを失うと、管理者に依頼しても復元できません。');
  });

  it('shows no such warning when a passkey can restore history too', () => {
    const html = render(true);
    expect(html).toContain(code);
    expect(html).not.toContain('復旧コードでのみ復元できます');
  });
});
