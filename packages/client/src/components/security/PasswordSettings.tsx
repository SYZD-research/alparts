import { useEffect, useState } from 'react';
import { ApiError, api } from '../../services/api';

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_BYTES = 72;

/** What is wrong with a new password, in the user's words, or null. */
export function newPasswordProblem(password: string, confirmation: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return 'パスワードは12文字以上にしてください。';
  if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) return 'パスワードが長すぎます。';
  if (password !== confirmation) return '確認用に入力したパスワードが一致しません。';
  return null;
}

function failureMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

/** onChanged reloads the login list, since a change can end other logins. */
export function PasswordSettings({ hasPasskey, onChanged }: { hasPasskey: boolean; onChanged: () => void }) {
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [passwordLogin, setPasswordLogin] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmingLoginChange, setConfirmingLoginChange] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.getPasswordLogin()
      .then((state) => { if (active) setPasswordLogin(state.enabled); })
      .catch(() => undefined);
    return () => { active = false; };
  }, []);

  const run = async (operation: () => Promise<string>, fallback: string) => {
    setBusy(true);
    setStatus(null);
    setError(null);
    try {
      setStatus(await operation());
    } catch (caught) {
      setError(failureMessage(caught, fallback));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-3" aria-label="パスワード">
      <h3 className="font-bold text-white">パスワード</h3>
      {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
      {status && <p role="status" className="text-sm text-discord-text">{status}</p>}
      <form
        className="space-y-2"
        onSubmit={(event) => {
          event.preventDefault();
          const problem = newPasswordProblem(newPassword, confirmation);
          if (problem) {
            setStatus(null);
            setError(problem);
            return;
          }
          void run(async () => {
            await api.changePassword(newPassword);
            setNewPassword('');
            setConfirmation('');
            onChanged();
            return 'パスワードを変更しました。ほかの端末ではログアウトしました。';
          }, 'パスワードを変更できませんでした。もう一度お試しください。');
        }}
      >
        <label className="block text-sm">
          新しいパスワード
          <input
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            className="mt-2 block w-full rounded bg-discord-bg p-3 text-discord-text"
          />
        </label>
        <label className="block text-sm">
          新しいパスワード（確認）
          <input
            type="password"
            autoComplete="new-password"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            className="mt-2 block w-full rounded bg-discord-bg p-3 text-discord-text"
          />
        </label>
        <p className="text-xs text-discord-muted">変更すると、ほかの端末ではログアウトします。</p>
        <button
          disabled={busy || !newPassword || !confirmation}
          className="rounded bg-discord-accent px-3 py-2 text-white disabled:opacity-50"
        >
          {busy ? '処理中…' : 'パスワードを変更'}
        </button>
      </form>
      {hasPasskey && passwordLogin !== null && (
        <div className="space-y-2 rounded bg-discord-bg p-3">
          <p className="text-sm text-discord-text">
            パスワードでのログイン: {passwordLogin ? 'オン' : 'オフ'}
          </p>
          {passwordLogin && (
            <p className="text-xs text-discord-muted">
              オフにすると、ログインにはパスキーが必要になります。パスワードでログインしているほかの端末はログアウトします。
            </p>
          )}
          {confirmingLoginChange ? (
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  const enabled = !passwordLogin;
                  void run(async () => {
                    await api.setPasswordLogin(enabled);
                    setPasswordLogin(enabled);
                    setConfirmingLoginChange(false);
                    onChanged();
                    return enabled
                      ? 'パスワードでのログインをオンにしました。'
                      : 'パスワードでのログインをオフにしました。';
                  }, '設定を変更できませんでした。もう一度お試しください。');
                }}
                className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                {busy ? '処理中…' : passwordLogin ? 'オフにする' : 'オンにする'}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setConfirmingLoginChange(false)}
                className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover"
              >
                キャンセル
              </button>
            </div>
          ) : (
            <button
              type="button"
              disabled={busy}
              onClick={() => setConfirmingLoginChange(true)}
              className="rounded border border-discord-muted px-3 py-2 text-sm disabled:opacity-50"
            >
              {passwordLogin ? 'パスワードでのログインをオフにする' : 'パスワードでのログインをオンにする'}
            </button>
          )}
        </div>
      )}
    </section>
  );
}
