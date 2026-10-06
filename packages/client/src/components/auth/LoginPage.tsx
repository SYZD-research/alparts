import { useState } from 'react';
import { canUsePasskeys } from '../../services/passkey.service';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth.store';
import { safeMessageReturnPath } from '../../stores/permalink-model';
import { LanguageSelect } from '../settings/LanguageSelect';
import { useT } from '../../i18n';

export function LoginPage() {
  const t = useT();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [inviteToken, setInviteToken] = useState('');
  // Set once a code was mailed for the address and invitation shown.
  const [codeSent, setCodeSent] = useState(false);
  const [emailCode, setEmailCode] = useState('');
  const { login, loginPasskey, register, isLoading, error } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  const resetCode = () => {
    setCodeSent(false);
    setEmailCode('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (isRegister) {
        const result = await register(email, password, displayName, inviteToken, codeSent ? emailCode : undefined);
        if (result === 'code-sent') {
          setCodeSent(true);
          return;
        }
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
          {isRegister ? t('アカウント作成') : t('おかえりなさい！')}
        </h1>
        <p className="text-discord-muted text-center mb-6">
          {isRegister ? t('alpartsへようこそ') : t('alpartsにログイン')}
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
            {t('パスキーでログイン')}
          </button>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <>
              <div>
                <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
                  {t('表示名')}
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
                  {t('招待コード')}
                </label>
                <input
                  type="password"
                  value={inviteToken}
                  onChange={(e) => {
                    setInviteToken(e.target.value);
                    resetCode();
                  }}
                  className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
                  required
                  autoComplete="one-time-code"
                />
              </div>
            </>
          )}

          <div>
            <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
              {t('メールアドレス')}
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                resetCode();
              }}
              className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
              {t('パスワード')}
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

          {isRegister && codeSent && (
            <div>
              <p role="status" className="mb-2 text-sm text-discord-text">
                {t('{email} に確認コードを送りました。メールに書かれた6桁のコードを入力してください。', { email })}
              </p>
              <label className="block text-xs font-bold text-discord-muted uppercase mb-2">
                {t('確認コード')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={emailCode}
                onChange={(e) => setEmailCode(e.target.value.replace(/[^0-9]/g, ''))}
                className="w-full px-3 py-2.5 bg-discord-bg rounded text-discord-text outline-none focus:ring-2 focus:ring-discord-accent"
                required
              />
              <button
                type="button"
                disabled={isLoading}
                onClick={() => {
                  setEmailCode('');
                  void register(email, password, displayName, inviteToken).catch(() => undefined);
                }}
                className="mt-2 text-sm text-discord-accent hover:underline disabled:opacity-50"
              >
                {t('コードを送り直す')}
              </button>
            </div>
          )}

          {error && <p className="text-discord-red text-sm">{error}</p>}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 bg-discord-accent hover:bg-discord-accent-hover rounded font-medium text-white transition-colors disabled:opacity-50"
          >
            {isLoading ? t('処理中...') : isRegister ? t('アカウント作成') : t('ログイン')}
          </button>
        </form>

        <p className="text-sm text-discord-muted mt-4 text-center">
          {isRegister ? t('すでにアカウントをお持ちですか？') : t('アカウントをお持ちでないですか？')}
          <button
            onClick={() => {
              setIsRegister(!isRegister);
              resetCode();
            }}
            className="text-discord-accent hover:underline ml-1"
          >
            {isRegister ? t('ログイン') : t('アカウント作成')}
          </button>
        </p>
        <LanguageSelect className="mt-6" />
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
