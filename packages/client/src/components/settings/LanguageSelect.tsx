import { useId } from 'react';
import { LANGUAGE_NAMES, useLocaleStore, useT, type LocalePreference } from '../../i18n';

export function LanguageSelect({ className = '' }: { className?: string }) {
  const t = useT();
  const id = useId();
  const preference = useLocaleStore((state) => state.preference);
  const setPreference = useLocaleStore((state) => state.setPreference);

  return (
    <div className={className}>
      <label htmlFor={id} className="block text-sm text-discord-muted">{t('表示言語')}</label>
      <select
        id={id}
        value={preference}
        onChange={(event) => setPreference(event.target.value as LocalePreference)}
        className="mt-1 block w-full rounded bg-discord-input px-3 py-2 text-sm text-discord-text"
      >
        <option value="system">{t('システムの設定に合わせる')}</option>
        <option value="ja" lang="ja">{LANGUAGE_NAMES.ja}</option>
        <option value="en" lang="en">{LANGUAGE_NAMES.en}</option>
      </select>
    </div>
  );
}
