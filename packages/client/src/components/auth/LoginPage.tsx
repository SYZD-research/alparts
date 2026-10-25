import { useState } from 'react';
import { canUsePasskeys } from '../../services/passkey.service';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth.store';
import { safeMessageReturnPath } from '../../stores/permalink-model';
import { LanguageSelect } from '../settings/LanguageSelect';
import { useT } from '../../i18n';
import { BrandMark } from '../ui/BrandMark';
import { Icon } from '../ui/Icon';

const LABEL = 'mb-1.5 block text-xs font-medium text-ink-soft';
const FIELD = 'w-full rounded-lg bg-field px-3 py-2.5 text-ink';
const TEXT_LINK = 'font-medium text-ink-strong underline decoration-line-strong underline-offset-4 hover:decoration-ink-strong';

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
    <div className="h-screen overflow-y-auto bg-canvas bg-[radial-gradient(56rem_28rem_at_50%_-8%,rgb(236_227_212/0.08),transparent)]">
      <div className="flex min-h-full items-center justify-center px-4 py-10">
        <div className="w-full max-w-md">
          <div className="mb-6 flex flex-col items-center text-center">
            <BrandMark size={52} className="mb-5 text-accent" />
            <h1 className="text-2xl font-semibold text-ink-strong">
              {isRegister ? t('アカウント作成') : t('おかえりなさい！')}
            </h1>
            <p className="mt-1.5 text-sm text-muted">
              {isRegister ? t('alpartsへようこそ') : t('alpartsにログイン')}
            </p>
          </div>
          <div className="rounded-2xl border border-line bg-panel p-6 shadow-2xl shadow-black/30 sm:p-8">
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
                className="mb-5 flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-3 font-semibold text-on-accent transition-colors hover:bg-accent-strong disabled:opacity-50"
              >
                <Icon name="key" />
                {t('パスキーでログイン')}
              </button>
            )}
            <form onSubmit={handleSubmit} className="space-y-4">
              {isRegister && (
                <>
                  <div>
                    <label className={LABEL}>
                      {t('表示名')}
                    </label>
                    <input
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      className={FIELD}
                      required
                    />
                  </div>
                  <div>
                    <label className={LABEL}>
                      {t('招待コード')}
                    </label>
                    <input
                      type="password"
                      value={inviteToken}
                      onChange={(e) => {
                        setInviteToken(e.target.value);
                        resetCode();
                      }}
                      className={FIELD}
                      required
                      autoComplete="one-time-code"
                    />
                  </div>
                </>
              )}

              <div>
                <label className={LABEL}>
                  {t('メールアドレス')}
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    resetCode();
                  }}
                  className={FIELD}
                  required
                />
              </div>

              <div>
                <label className={LABEL}>
                  {t('パスワード')}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={FIELD}
                  required
                  minLength={12}
                  maxLength={72}
                />
              </div>

              {isRegister && codeSent && (
                <div>
                  <p role="status" className="mb-2 text-sm text-ink">
                    {t('{email} に確認コードを送りました。メールに書かれた6桁のコードを入力してください。', { email })}
                  </p>
                  <label className={LABEL}>
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
                    className={FIELD}
                    required
                  />
                  <button
                    type="button"
                    disabled={isLoading}
                    onClick={() => {
                      setEmailCode('');
                      void register(email, password, displayName, inviteToken).catch(() => undefined);
                    }}
                    className={`mt-2 text-sm ${TEXT_LINK} disabled:opacity-50`}
                  >
                    {t('コードを送り直す')}
                  </button>
                </div>
              )}

              {error && <p className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{error}</p>}

              <button
                type="submit"
                disabled={isLoading}
                className="w-full rounded-xl bg-accent py-2.5 font-medium text-on-accent transition-colors hover:bg-accent-strong disabled:opacity-50"
              >
                {isLoading ? t('処理中...') : isRegister ? t('アカウント作成') : t('ログイン')}
              </button>
            </form>
          </div>

          <p className="mt-5 text-center text-sm text-muted">
            {isRegister ? t('すでにアカウントをお持ちですか？') : t('アカウントをお持ちでないですか？')}
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                resetCode();
              }}
              className={`ml-1 ${TEXT_LINK}`}
            >
              {isRegister ? t('ログイン') : t('アカウント作成')}
            </button>
          </p>
          <LanguageSelect className="mx-auto mt-6 max-w-60" />
        </div>
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
