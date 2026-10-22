import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { translate, type MessageKey, type MessageParams } from '../../i18n';
import { NewRecoveryCode, restoreResultMessage } from './HistoryRecoverySettings';

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

describe('restore result', () => {
  const ja = (key: MessageKey, params?: MessageParams) => translate('ja', key, params);
  const en = (key: MessageKey, params?: MessageParams) => translate('en', key, params);

  it('says how many items were restored', () => {
    expect(restoreResultMessage(ja, { restored: 3, failed: 0 })).toBe('履歴を復元しました（3件）。');
    expect(restoreResultMessage(en, { restored: 1, failed: 0 })).toBe('Restored 1 item of history.');
  });

  it('also says how many could not be restored', () => {
    expect(restoreResultMessage(ja, { restored: 2, failed: 1 })).toBe('履歴を復元しました（2件）。1件は復元できませんでした。');
    expect(restoreResultMessage(en, { restored: 2, failed: 3 })).toBe('Restored 2 items of history. 3 could not be restored.');
    expect(restoreResultMessage(en, { restored: 0, failed: 1 })).toBe('Restored 0 items of history. 1 could not be restored.');
  });
});
