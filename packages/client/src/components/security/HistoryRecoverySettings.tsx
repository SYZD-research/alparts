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
import { msg, useT, type MessageKey, type MessageParams } from '../../i18n';
type RecoveryPlan = Awaited<ReturnType<typeof createRecoveryPlan>>;
const CODE_ONLY_WARNING = msg('保存済みの履歴は、復旧コードでのみ復元できます。コードを失うと、管理者に依頼しても復元できません。');
/** What the user is told once a restore has finished. */
export function restoreResultMessage(
  t: (key: MessageKey, params?: MessageParams) => string,
  { restored, failed }: { restored: number; failed: number },
): string {
  return failed > 0
    ? t('履歴を復元しました（{count}件）。{failed}件は復元できませんでした。', { count: restored, failed })
    : t('履歴を復元しました（{count}件）。', { count: restored });
}
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
  const [plan, setPlan] = useState<RecoveryPlan | null>(null);
  const [code, setCode] = useState('');
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
      <h3 className="font-semibold text-ink-strong">{t('履歴の復元')}</h3>
      <p className="text-sm text-muted">
        {t('対応するパスキーで設定すると、パスキーまたは復旧コードで保存済みの履歴を復元できます。両方を失うと、管理者に依頼しても復元できません。')}
      </p>
      {needsUpdate && (
        <p role="alert" className="text-sm text-ink">
          {pending
            ? t('この復旧コードは、以前から使っている端末で更新が必要です。その端末で復旧コードを入力してください。')
            : t('復元の設定を更新するため、保管済みの復旧コードを入力してください。更新が終わるまで、この端末を保持してください。')}
        </p>
      )}
      {message && (
        <p role="status" className="text-sm text-ink">
          {message}
        </p>
      )}
      {passkeyAvailable && (
        <button disabled={busy} className="rounded-lg bg-accent px-3 py-2 text-on-accent"
          onClick={() => { void run(async () => {
            const result = await restoreHistory();
            refreshRestoredHistory();
            return restoreResultMessage(t, result);
          }); }}>
          {t('パスキーで履歴を復元')}
        </button>
      )}
      {configured && !passkeyAvailable && (
        <p className="text-sm text-ink">{t(CODE_ONLY_WARNING)}</p>
      )}
      {!pending && !plan && configured !== null && (
        <div className="flex flex-wrap gap-3">
          {!configured && (
            <button
              disabled={busy}
              className="rounded-lg bg-accent px-3 py-2 text-on-accent"
              onClick={() => {
                void run(async () => {
                  setPlan(await createRecoveryPlan(() => setMessage(t('パスキーで本人確認してください。'))));
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
              className="rounded-lg border border-line-strong px-3 py-2 text-ink transition-colors hover:bg-hover"
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
              className="rounded-lg border border-danger px-3 py-2 text-danger"
              onClick={() => setConfirmDisable(true)}
            >
              {t('復旧コードを無効にする')}
            </button>
          )}
        </div>
      )}
      {confirmDisable && (
        <div className="space-y-3 rounded-lg border border-danger p-3">
          <p className="text-sm">
            {t('保管したコードと、このコードで復元するために保存した履歴が使えなくなります。端末内の履歴は残ります。')}
          </p>
          <button
            disabled={busy}
            className="rounded-lg bg-danger px-3 py-2 text-white"
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
        <NewRecoveryCode
          plan={plan}
          busy={busy}
          onEnable={() => {
            void run(async () => {
              await enableHistoryRecovery(plan);
              setPlan(null);
              setConfigured(true);
              setPasskeyAvailable(plan.passkeyProtected);
              setNeedsUpdate(false);
              return t('復元を有効にしました。「履歴を保存」で以前の履歴も保存してください。今後受け取る履歴はこの端末から保存します。');
            });
          }}
          onCancel={() => setPlan(null)}
        />
      )}
      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const result = await restoreHistory(code);
            setCode('');
            refreshRestoredHistory();
            return restoreResultMessage(t, result);
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
            className="mt-2 block w-full rounded-lg bg-canvas p-3 text-ink"
          />
        </label>
        <button
          disabled={busy || !code.trim()}
          className="rounded-lg bg-accent px-3 py-2 text-on-accent disabled:opacity-50"
        >
          {busy ? t('処理中…') : t('履歴を復元')}
        </button>
      </form>
    </section>
  );
}
/** Shows a new recovery code until the user has saved it and turns restore on. */
export function NewRecoveryCode({ plan, busy, onEnable, onCancel }: {
  plan: Pick<RecoveryPlan, 'code' | 'passkeyProtected'>;
  busy: boolean;
  onEnable: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [saved, setSaved] = useState(false);
  return (
    <div className="space-y-3 rounded-xl border border-line p-3">
      <p className="text-sm text-ink">
        {t('このコードを知っている人は履歴を復元できます。他の人に渡さず、この端末とは別の安全な場所に保管してください。')}
      </p>
      {!plan.passkeyProtected && (
        <p className="text-sm text-ink">{t(CODE_ONLY_WARNING)}</p>
      )}
      <code className="block break-all select-all rounded-lg bg-canvas p-3 text-ink-strong">
        {plan.code}
      </code>
      <label className="block text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />{' '}
        {t('復旧コードを保管しました')}
      </label>
      <button
        disabled={!saved || busy}
        className="rounded-lg bg-accent px-3 py-2 text-on-accent disabled:opacity-50"
        onClick={onEnable}
      >
        {t('復元を有効にする')}
      </button>
      <button disabled={busy} className="ml-3" onClick={onCancel}>
        {t('キャンセル')}
      </button>
    </div>
  );
}
