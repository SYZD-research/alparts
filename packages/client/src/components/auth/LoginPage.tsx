import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth.store';

export function LoginPage() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const { login, register, isLoading, error } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (isRegister) {
        await register(email, password, displayName);
      } else {
        await login(email, password);
      }
      navigate('/');
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

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
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
              minLength={8}
            />
          </div>

          {error && (
            <p className="text-discord-red text-sm">{error}</p>
          )}

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
            onClick={() => { setIsRegister(!isRegister); }}
            className="text-discord-accent hover:underline ml-1"
          >
            {isRegister ? 'ログイン' : 'アカウント作成'}
          </button>
        </p>
      </div>
    </div>
  );
}
