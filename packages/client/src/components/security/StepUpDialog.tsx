import { useEffect, useState } from 'react';
import { create } from 'zustand';
import { api } from '../../services/api';
import {
  canUsePasskeys,
  completeStepUp,
  type AuthenticationOptions,
} from '../../services/passkey.service';
import { Dialog } from '../ui/Dialog';
import { useT } from '../../i18n';
interface Request {
  purpose: string;
  resolve: (token: string) => void;
  reject: () => void;
}
const useStepUp = create<{ request: Request | null }>(() => ({
  request: null,
}));
api.setStepUpHandler(
  (purpose, signal) =>
    new Promise((resolve, reject) => {
      if (useStepUp.getState().request || signal?.aborted) {
        reject(new Error('VERIFICATION_CANCELLED'));
        return;
      }
      const cleanup = () => {
        signal?.removeEventListener('abort', cancel);
        useStepUp.setState({ request: null });
      };
      const cancel = () => {
        cleanup();
        reject(new Error('VERIFICATION_CANCELLED'));
      };
      signal?.addEventListener('abort', cancel, { once: true });
      useStepUp.setState({
        request: {
          purpose,
          resolve: (token) => {
            cleanup();
            resolve(token);
          },
          reject: cancel,
        },
      });
    }),
);
export function StepUpDialog() {
  const t = useT();
  const request = useStepUp((s) => s.request);
  const [options, setOptions] = useState<AuthenticationOptions | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setOptions(null);
    setPassword('');
    setError(false);
    setBusy(false);
    if (!request) return;
    let active = true;
    api
      .securityRequest<AuthenticationOptions>('/auth/step-up/options', {
        purpose: request.purpose,
      })
      .then((value) => {
        if (active) setOptions(value);
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
    };
  }, [request]);
  return (
    <Dialog
      open={!!request}
      onClose={() => request?.reject()}
      title={t('本人確認')}
      description={t('この操作を続けるため、本人確認を行ってください。')}
    >
      {error && (
        <p role="alert" className="text-discord-red">
          {t('本人確認を完了できませんでした。閉じてからもう一度お試しください。')}
        </p>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!request || !options || busy || (!options.passwordAllowed && !canUsePasskeys()))
            return;
          setBusy(true);
          void completeStepUp(request.purpose, options, password)
            .then(({ token }) => request.resolve(token))
            .catch(() => {
              setError(true);
              setOptions(null);
            })
            .finally(() => {
              setPassword('');
              setBusy(false);
            });
        }}
      >
        {options?.passwordAllowed && (
          <label className="block text-sm text-discord-text">
            {t('現在のパスワード')}
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-2 block w-full rounded bg-discord-bg p-3"
              required
            />
          </label>
        )}
        {options && !options.passwordAllowed && !canUsePasskeys() && (
          <p role="status" className="text-sm text-discord-text">
            {t('この操作は、対応するブラウザーでWeb版を開いて行ってください。パスキーでの本人確認が必要です。')}
          </p>
        )}
        <div className="mt-4 flex justify-end gap-3">
          <button type="button" onClick={() => request?.reject()}>
            {t('キャンセル')}
          </button>
          <button
            type="submit"
            disabled={!options || busy || (!options.passwordAllowed && !canUsePasskeys())}
            className="rounded bg-discord-accent px-4 py-2 text-white disabled:opacity-50"
          >
            {busy ? t('確認中…') : options?.passwordAllowed ? t('確認する') : t('パスキーで確認')}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
