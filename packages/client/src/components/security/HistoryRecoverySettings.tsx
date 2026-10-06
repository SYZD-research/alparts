import { useEffect, useState } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useChannelStore } from '../../stores/channel.store';
import {
  createRecoveryPlan,
  enableHistoryRecovery,
  restoreHistory,
  backupAvailableHistory,
  getHistoryRecoveryConfiguration,
  disableHistoryRecovery,
} from '../../services/recovery.service';
import { useT } from '../../i18n';
export function HistoryRecoverySettings({
  pending = false,
  onRestored,
}: {
  pending?: boolean;
  onRestored?: () => void;
}) {
  const t = useT();
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [needsUpdate, setNeedsUpdate] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [passkeyAvailable, setPasskeyAvailable] = useState(false);
  useEffect(() => {
    void getHistoryRecoveryConfiguration()
      .then((config) => {
        setConfigured(Boolean(config));
        setPasskeyAvailable(Boolean(config?.passkeyWrap));
        setNeedsUpdate(!!config && !config.accessConfigured);
      })
      .catch(() => setMessage(t('復元の設定を読み込めませんでした。画面を開き直してください。')));
  }, []);
  const [plan, setPlan] = useState<Awaited<ReturnType<typeof createRecoveryPlan>> | null>(null);
  const [code, setCode] = useState('');
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const refreshRestoredHistory = () => {
    setConfigured(true);
    setNeedsUpdate(false);
    if (onRestored) onRestored();
    else {
      const messages = useMessageStore.getState();
      for (const channelId of Object.keys(messages.eventsByChannel))
        messages.retryUnavailableMessages(channelId);
      const activeChannelId = useChannelStore.getState().activeChannelId;
      if (activeChannelId) void messages.loadMessages(activeChannelId);
    }
  };
  const run = async (operation: () => Promise<string>) => {
    setBusy(true);
    setMessage('');
    try {
      setMessage(await operation());
    } catch (error) {
      setMessage(error instanceof Error && error.message === 'PASSKEY_VAULT_UNAVAILABLE'
        ? t('この環境ではパスキーを利用できません。対応するブラウザーとパスキーでWeb版を開くか、保管済みの復旧コードで復元してください。')
        : t('操作を完了できませんでした。入力内容を確認して、もう一度お試しください。'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="space-y-3" aria-label={t('履歴の復元')}>
      <h3 className="font-bold text-white">{t('履歴の復元')}</h3>
      <p className="text-sm text-discord-muted">
        {t('対応するパスキーで設定すると、パスキーまたは復旧コードで保存済みの履歴を復元できます。両方を失うと、管理者に依頼しても復元できません。')}
      </p>
      {needsUpdate && (
        <p role="alert" className="text-sm text-discord-text">
          {pending
            ? t('この復旧コードは、以前から使っている端末で更新が必要です。その端末で復旧コードを入力してください。')
            : t('復元の設定を更新するため、保管済みの復旧コードを入力してください。更新が終わるまで、この端末を保持してください。')}
        </p>
      )}
      {message && (
        <p role="status" className="text-sm text-discord-text">
          {message}
        </p>
      )}
      {passkeyAvailable && (
        <button disabled={busy} className="rounded bg-discord-accent px-3 py-2 text-white"
          onClick={() => { void run(async () => {
            const count = await restoreHistory();
            refreshRestoredHistory();
            return t('履歴を復元しました（{count}件）。', { count });
          }); }}>
          {t('パスキーで履歴を復元')}
        </button>
      )}
      {!pending && !plan && configured !== null && (
        <div className="flex flex-wrap gap-3">
          {!configured && (
            <button
              disabled={busy}
              className="rounded bg-discord-accent px-3 py-2 text-white"
              onClick={() => {
                void run(async () => {
                  setMessage(t('パスキーで本人確認してください。'));
                  setPlan(await createRecoveryPlan());
                  return t('復旧コードを安全な場所に保管してください。');
                });
              }}
            >
              {t('復旧コードを作成')}
            </button>
          )}
          {configured && (
            <button
              disabled={busy}
              className="rounded border border-discord-muted px-3 py-2"
              onClick={() => {
                void run(
                  async () => t('履歴の保存を確認しました（{count}件）。', { count: await backupAvailableHistory() }),
                );
              }}
            >
              {t('履歴を保存')}
            </button>
          )}
          {configured && (
            <button
              disabled={busy}
              className="rounded border border-discord-red px-3 py-2 text-discord-red"
              onClick={() => setConfirmDisable(true)}
            >
              {t('復旧コードを無効にする')}
            </button>
          )}
        </div>
      )}
      {confirmDisable && (
        <div className="space-y-3 rounded border border-discord-red p-3">
          <p className="text-sm">
            {t('保管したコードと、このコードで復元するために保存した履歴が使えなくなります。端末内の履歴は残ります。')}
          </p>
          <button
            disabled={busy}
            className="rounded bg-discord-red px-3 py-2 text-white"
            onClick={() => {
              void run(async () => {
                await disableHistoryRecovery();
                setConfigured(false);
                setPasskeyAvailable(false);
                setNeedsUpdate(false);
                setConfirmDisable(false);
                return t('復旧コードを無効にしました。');
              });
            }}
          >
            {t('無効にする')}
          </button>
          <button disabled={busy} className="ml-3" onClick={() => setConfirmDisable(false)}>
            {t('キャンセル')}
          </button>
        </div>
      )}
      {plan && (
        <div className="space-y-3 rounded border border-discord-muted p-3">
          <p className="text-sm text-discord-text">
            {t('このコードを知っている人は履歴を復元できます。他の人に渡さず、この端末とは別の安全な場所に保管してください。')}
          </p>
          <code className="block break-all select-all rounded bg-discord-bg p-3 text-white">
            {plan.code}
          </code>
          <label className="block text-sm">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />{' '}
            {t('復旧コードを保管しました')}
          </label>
          <button
            disabled={!saved || busy}
            className="rounded bg-discord-accent px-3 py-2 text-white disabled:opacity-50"
            onClick={() => {
              void run(async () => {
                await enableHistoryRecovery(plan);
                setPlan(null);
                setSaved(false);
                setConfigured(true);
                setPasskeyAvailable(true);
                setNeedsUpdate(false);
                return t('復元を有効にしました。「履歴を保存」で以前の履歴も保存してください。今後受け取る履歴はこの端末から保存します。');
              });
            }}
          >
            {t('復元を有効にする')}
          </button>
          <button
            disabled={busy}
            className="ml-3"
            onClick={() => {
              setPlan(null);
              setSaved(false);
            }}
          >
            {t('キャンセル')}
          </button>
        </div>
      )}
      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const count = await restoreHistory(code);
            setCode('');
            refreshRestoredHistory();
            return t('履歴を復元しました（{count}件）。', { count });
          });
        }}
      >
        <label className="block text-sm">
          {t('保管済みの復旧コード')}
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="mt-2 block w-full rounded bg-discord-bg p-3 text-discord-text"
          />
        </label>
        <button
          disabled={busy || !code.trim()}
          className="rounded bg-discord-accent px-3 py-2 text-white disabled:opacity-50"
        >
          {busy ? t('処理中…') : t('履歴を復元')}
        </button>
      </form>
    </section>
  );
}
