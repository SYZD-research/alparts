import { useEffect, useState } from 'react';
import { DESKTOP_IDLE_LOCK_MINUTES, getDesktopBridge } from '../../services/desktop.service';
import { useT } from '../../i18n';

export function DesktopSecuritySettings() {
  const t = useT();
  const bridge = getDesktopBridge();
  const [minutes, setMinutes] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!bridge) return;
    void bridge.getInfo()
      .then((info) => setMinutes(info.idleLockMinutes))
      .catch(() => setError(t('自動ロックの設定を読み込めませんでした。')));
  }, [bridge]);

  if (!bridge) return null;

  const update = async (value: number) => {
    setSaving(true);
    setError(null);
    try {
      setMinutes(await bridge.setIdleLockMinutes(value));
    } catch {
      setError(t('自動ロックの設定を保存できませんでした。'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section aria-labelledby="desktop-security-heading">
      <h3 id="desktop-security-heading" className="mb-3 font-bold text-white">{t('アプリのロック')}</h3>
      <div className="rounded bg-discord-bg p-3">
        <label className="block text-sm text-discord-text">
          {t('操作がないときに自動でロック')}
          <select
            value={minutes ?? 5}
            disabled={minutes === null || saving}
            onChange={(event) => { void update(Number(event.target.value)); }}
            className="mt-2 block w-full rounded bg-discord-input px-3 py-2 text-discord-text disabled:opacity-50"
          >
            {DESKTOP_IDLE_LOCK_MINUTES.map((value) => <option key={value} value={value}>{t('{count}分後', { count: value })}</option>)}
          </select>
        </label>
        <button type="button" onClick={() => { void bridge.lockNow(); }} className="mt-3 rounded border border-discord-hover px-3 py-2 text-sm text-discord-text hover:bg-discord-hover">
          {t('今すぐロック')}
        </button>
        {error && <p role="alert" className="mt-2 text-xs text-discord-red">{error}</p>}
      </div>
    </section>
  );
}
