import { useEffect, useState } from 'react';
import type { User } from '@alparts/shared';
import type { AlpartsDesktopInfo } from '../../types/desktop';
import { getDesktopBridge } from '../../services/desktop.service';
import { lockAuthenticatedClient, unlockAuthenticatedClient, useAuthStore } from '../../stores/auth.store';
import { useT } from '../../i18n';
import { LanguageSelect } from '../settings/LanguageSelect';

type BoundaryState =
  | { kind: 'loading' }
  | { kind: 'ready'; info: AlpartsDesktopInfo; showConnection: boolean }
  | { kind: 'error'; message: string };

export function DesktopBoundary({ children }: { children: React.ReactNode }) {
  const t = useT();
  const bridge = getDesktopBridge();
  const [state, setState] = useState<BoundaryState>(bridge ? { kind: 'loading' } : {
    kind: 'ready',
    info: webInfo(),
    showConnection: false,
  });
  const [lockState, setLockState] = useState<{ locked: boolean; user: User | null }>({
    locked: false,
    user: null,
  });

  const refresh = async () => {
    if (!bridge) return;
    try {
      const info = await bridge.getInfo();
      if (info.locked) setLockState((current) => ({ ...current, locked: true }));
      setState({ kind: 'ready', info, showConnection: !info.serverUrl });
    } catch {
      setState({ kind: 'error', message: t('アプリを開始できませんでした。もう一度お試しください。') });
    }
  };

  useEffect(() => {
    if (!bridge) return;
    void refresh();
    const stopLock = bridge.onLock(() => {
      const user = lockAuthenticatedClient();
      if (user) setLockState({ locked: true, user });
      else void bridge.unlockComplete();
    });
    const stopSettings = bridge.onShowConnectionSettings(() => {
      setState((current) => current.kind === 'ready' ? { ...current, showConnection: true } : current);
    });
    return () => {
      stopLock();
      stopSettings();
    };
  }, [bridge]);

  if (!bridge) return <>{children}</>;
  if (state.kind === 'loading') return <FullPageStatus message={t('アプリを準備しています…')} />;
  if (state.kind === 'error') {
    return <FullPageStatus message={state.message} actionLabel={t('もう一度試す')} onAction={() => { setState({ kind: 'loading' }); void refresh(); }} />;
  }
  if (!state.info.secureStorageReady) {
    return (
      <FullPageStatus
        message={t('この端末ではデータを安全に保存できないため、アプリを開始できません。端末のロックを有効にしてから、もう一度お試しください。')}
        actionLabel={t('もう一度試す')}
        onAction={() => { setState({ kind: 'loading' }); void refresh(); }}
        alert
      />
    );
  }
  if (lockState.locked) {
    return <AppUnlock user={lockState.user} onUnlocked={() => setLockState({ locked: false, user: null })} />;
  }
  if (state.showConnection || !state.info.serverUrl) {
    return (
      <ConnectionSetup
        info={state.info}
        onCancel={state.info.serverUrl ? () => setState({ ...state, showConnection: false }) : undefined}
      />
    );
  }
  return <>{children}</>;
}

function ConnectionSetup({ info, onCancel }: { info: AlpartsDesktopInfo; onCancel?: () => void }) {
  const t = useT();
  const bridge = getDesktopBridge()!;
  const [serverUrl, setServerUrl] = useState(info.serverUrl || '');
  const [confirmed, setConfirmed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const changed = Boolean(info.serverUrl && serverUrl.trim().replace(/\/$/, '') !== info.serverUrl);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (saving || (changed && !confirmed)) return;
    setSaving(true);
    setError(null);
    try {
      await bridge.configureServer(serverUrl.trim());
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : '';
      setError(message.includes('INSECURE_SERVER_URL')
        ? t('この接続先は安全に利用できません。管理者から案内された接続先を確認してください。')
        : t('接続先を保存できませんでした。入力内容を確認してください。'));
      setSaving(false);
    }
  };

  return (
    <main className="flex h-screen items-center justify-center bg-discord-bg p-6">
      <section aria-labelledby="desktop-setup-title" className="w-full max-w-lg rounded-lg bg-discord-sidebar p-8 shadow-2xl">
        <h1 id="desktop-setup-title" className="text-2xl font-bold text-white">{t('接続先を設定')}</h1>
        <p className="mt-2 text-sm text-discord-muted">{t('管理者から案内されたアドレスを入力してください。')}</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <label className="block text-sm text-discord-text">
            {t('接続先')}
            <input
              autoFocus
              required
              type="url"
              inputMode="url"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="https://chat.example.com"
              value={serverUrl}
              onChange={(event) => { setServerUrl(event.target.value); setConfirmed(false); }}
              disabled={saving || info.serverManaged}
              className="mt-2 w-full rounded bg-discord-input px-3 py-2.5 text-discord-text outline-none focus:ring-2 focus:ring-discord-accent disabled:opacity-60"
            />
          </label>
          {changed && (
            <label className="flex gap-3 rounded border border-discord-red/60 bg-discord-red/10 p-3 text-sm text-discord-text">
              <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-0.5" />
              <span>{t('接続先を変更すると、現在の接続先についてこの端末に保存した下書きなどが削除されます。')}</span>
            </label>
          )}
          {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
          <div className="flex justify-end gap-2">
            {onCancel && <button type="button" onClick={onCancel} disabled={saving} className="rounded px-4 py-2 text-sm text-discord-muted hover:bg-discord-hover">{t('キャンセル')}</button>}
            <button type="submit" disabled={saving || !serverUrl.trim() || (changed && !confirmed) || info.serverManaged} className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
              {saving ? t('接続しています…') : t('接続する')}
            </button>
          </div>
        </form>
        <LanguageSelect className="mt-6" />
      </section>
    </main>
  );
}

function AppUnlock({ user, onUnlocked }: { user: User | null; onUnlocked: () => void }) {
  const t = useT();
  const bridge = getDesktopBridge()!;
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await unlockAuthenticatedClient(user, password);
      await bridge.unlockComplete();
      setPassword('');
      onUnlocked();
    } catch {
      setError(t('ロックを解除できませんでした。パスワードと接続を確認してください。'));
    } finally {
      setSubmitting(false);
    }
  };

  const returnToLogin = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await useAuthStore.getState().logout();
      await bridge.unlockComplete();
      onUnlocked();
    } catch {
      setError(t('ログイン画面へ戻れませんでした。もう一度お試しください。'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="flex h-screen items-center justify-center bg-discord-bg p-6">
      <section aria-labelledby="desktop-unlock-title" className="w-full max-w-md rounded-lg bg-discord-sidebar p-8 shadow-2xl">
        <h1 id="desktop-unlock-title" className="text-2xl font-bold text-white">{t('アプリはロックされています')}</h1>
        <p className="mt-2 text-sm text-discord-muted">
          {user ? t('{name} として続けるにはパスワードを入力してください。', { name: user.displayName }) : t('続けるにはパスワードを入力してください。')}
        </p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <label className="block text-sm text-discord-text">
            {t('パスワード')}
            <input
              autoFocus
              required
              type="password"
              minLength={1}
              maxLength={72}
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-2 w-full rounded bg-discord-input px-3 py-2.5 text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
            />
          </label>
          {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
          <button type="submit" disabled={submitting} className="w-full rounded bg-discord-accent px-4 py-2.5 font-medium text-white disabled:opacity-40">
            {submitting ? t('確認しています…') : t('ロックを解除')}
          </button>
          <button type="button" disabled={submitting} onClick={() => { void returnToLogin(); }} className="w-full rounded px-4 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-40">
            {t('ログイン画面に戻る')}
          </button>
        </form>
      </section>
    </main>
  );
}

function FullPageStatus({ message, actionLabel, onAction, alert = false }: {
  message: string;
  actionLabel?: string;
  onAction?: () => void;
  alert?: boolean;
}) {
  return (
    <main className="flex h-screen items-center justify-center bg-discord-bg p-6">
      <div role={alert ? 'alert' : 'status'} className="max-w-lg rounded-lg bg-discord-sidebar p-8 text-center text-discord-text shadow-2xl">
        <p>{message}</p>
        {actionLabel && onAction && <button type="button" onClick={onAction} className="mt-5 rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white">{actionLabel}</button>}
      </div>
    </main>
  );
}

function webInfo(): AlpartsDesktopInfo {
  return {
    platform: 'linux',
    version: '',
    serverUrl: null,
    idleLockMinutes: 5,
    locked: false,
    secureStorageReady: true,
    serverManaged: false,
  };
}
