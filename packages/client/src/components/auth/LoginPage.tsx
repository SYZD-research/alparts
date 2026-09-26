import { useState } from 'react';
import { canUsePasskeys } from '../../services/passkey.service';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth.store';
import { safeMessageReturnPath } from '../../stores/permalink-model';

export function LoginPage() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [inviteToken, setInviteToken] = useState('');
  const { login, loginPasskey, register, isLoading, error } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (isRegister) {
        await register(email, password, displayName, inviteToken);
      } else {
        await login(email, password);
      }
      const returnTo = readSafeReturnPath(location.state);
      navigate(returnTo, { replace: true });
    } catch {
      // Error handled in store
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-discord-bg">
      <div className="w-full max-w-md p-8 bg-discord-sidebar rounded-lg">
        <h1 className="text-2xl font-bold text-center text-white mb-2">
          {isRegister ? 'アカウント作成' : 'おかえりなさい！'}
        </h1>
        <p className="text-discord-muted text-center mb-6">
          {isRegister ? 'alpartsへようこそ' : 'alpartsにログイン'}
        </p>

        {!isRegister && canUsePasskeys() && (
          <button
            type="button"
            disabled={isLoading}
            onClick={() => {
              void loginPasskey()
                .then(() =>
                  navigate(readSafeReturnPath(location.state), {
                    replace: true,
                  }),
                )
                .catch(() => undefined);
            }}
            className="mb-4 w-full rounded bg-discord-accent px-4 py-3 font-bold text-white disabled:opacity-50"
          >
            パスキーでログイン
          </button>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <>
              <div>
                <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
                  表示名
                </label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
                  招待コード
                </label>
                <input
                  type="password"
                  value={inviteToken}
                  onChange={(e) => setInviteToken(e.target.value)}
                  className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
                  required
                  autoComplete="one-time-code"
                />
              </div>
            </>
          )}

          <div>
            <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
              メールアドレス
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
              パスワード
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
              required
              minLength={12}
              maxLength={72}
            />
          </div>

          {error && <p className="text-discord-red text-sm">{error}</p>}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 bg-discord-accent hover:bg-discord-accent-hover rounded font-medium text-white transition-colors disabled:opacity-50"
          >
            {isLoading ? '処理中...' : isRegister ? 'アカウント作成' : 'ログイン'}
          </button>
        </form>

        <p className="text-sm text-discord-muted mt-4 text-center">
          {isRegister ? 'すでにアカウントをお持ちですか？' : 'アカウントをお持ちでないですか？'}
          <button
            onClick={() => {
              setIsRegister(!isRegister);
            }}
            className="text-discord-accent hover:underline ml-1"
          >
            {isRegister ? 'ログイン' : 'アカウント作成'}
          </button>
        </p>
      </div>
    </div>
  );
}

function readSafeReturnPath(state: unknown): string {
  if (!state || typeof state !== 'object') return '/';
  const returnTo = (state as { returnTo?: unknown }).returnTo;
  if (typeof returnTo !== 'string') return '/';
  return safeMessageReturnPath(returnTo);
}
