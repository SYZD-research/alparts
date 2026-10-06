import { useState } from 'react';
import { getActiveDevice } from '../../services/crypto.service';
import { verifiedDirectory } from '../../services/directory.service';
import { useT } from '../../i18n';

/** The comparison must travel outside the server being checked. */
export function DirectoryCheckpoint() {
  const t = useT();
  const [code, setCode] = useState('');
  const [otherCode, setOtherCode] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (compare: boolean) => {
    setBusy(true);
    setMessage('');
    try {
      const userId = getActiveDevice().userId;
      if (compare) {
        const match = /^(\d{1,4})-([a-f0-9]{64})$/i.exec(otherCode.trim());
        if (!match || Number(match[1]) < 1 || Number(match[1]) > 8192)
          throw new Error('INVALID_CODE');
        await verifiedDirectory(userId, undefined, {
          userId,
          sequence: Number(match[1]),
          hash: match[2].toLowerCase(),
        });
        setMessage(t('同じ端末一覧から続いていることを確認しました。'));
      } else {
        const { head } = await verifiedDirectory(userId);
        setCode(`${head.sequence}-${head.hash}`);
      }
    } catch {
      setMessage(t('一致を確認できませんでした。知らない端末は承認せず、コードを確認してください。'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="space-y-3" aria-label={t('端末一覧の確認')}>
      <h3 className="font-bold text-white">{t('端末一覧の確認')}</h3>
      <p className="text-sm text-discord-muted">
        {t('自分の別の端末と確認コードを照合できます。コードはその端末の画面で直接確認してください。')}
      </p>
      <button
        disabled={busy}
        className="rounded border border-discord-muted px-3 py-2"
        onClick={() => {
          void run(false);
        }}
      >
        {t('確認コードを表示')}
      </button>
      {code && (
        <code className="block select-all break-all rounded bg-discord-bg p-3 text-sm">{code}</code>
      )}
      <form
        className="space-y-2"
        onSubmit={(event) => {
          event.preventDefault();
          void run(true);
        }}
      >
        <label className="block text-sm">
          {t('別の端末の確認コード')}
          <input
            value={otherCode}
            onChange={(event) => setOtherCode(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="mt-2 block w-full rounded bg-discord-bg p-3"
          />
        </label>
        <button
          disabled={busy || !otherCode.trim()}
          className="rounded bg-discord-accent px-3 py-2 text-white disabled:opacity-50"
        >
          {t('照合する')}
        </button>
      </form>
      {message && (
        <p role="status" className="text-sm">
          {message}
        </p>
      )}
    </section>
  );
}
