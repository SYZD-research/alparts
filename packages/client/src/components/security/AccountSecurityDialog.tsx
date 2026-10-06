import { getSocket } from '../../services/socket';
import { DirectoryCheckpoint } from './DirectoryCheckpoint';
import { canUsePasskeys, registerPasskey } from '../../services/passkey.service';
import { deviceDecision } from '../../services/directory.service';
import { sha256 } from '../../services/security-storage';
import { HistoryRecoverySettings } from './HistoryRecoverySettings';
import { PasswordSettings } from './PasswordSettings';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Device } from '@alparts/shared';
import { ApiError, api, type AuthSession } from '../../services/api';
import { getActiveDevice } from '../../services/crypto.service';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { Dialog } from '../ui/Dialog';
import { DesktopSecuritySettings } from '../desktop/DesktopSecuritySettings';
import { intlLocale, t, useT } from '../../i18n';

type PendingAction =
  | { kind: 'approve'; id: string; label: string; requiresLogin: false }
  | { kind: 'session'; id: string; label: string; requiresLogin: boolean }
  | { kind: 'all-sessions'; label: string; requiresLogin: true }
  | { kind: 'device'; id: string; label: string; requiresLogin: boolean };

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('不明') : date.toLocaleString(intlLocale());
}

function sessionDescription(session: AuthSession): string {
  const platform = friendlyPlatform(session.deviceInfo?.platform);
  const browser = friendlyBrowser(session.deviceInfo?.browser);
  return [platform, browser].filter(Boolean).join(t('・')) || t('名前のない端末');
}

function friendlyPlatform(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (/iphone/i.test(value)) return 'iPhone';
  if (/ipad/i.test(value)) return 'iPad';
  if (/android/i.test(value)) return 'Android';
  if (/win/i.test(value)) return 'Windows';
  if (/mac/i.test(value)) return 'Mac';
  if (/linux/i.test(value)) return 'Linux';
  return null;
}

function friendlyBrowser(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (/edg\//i.test(value)) return 'Edge';
  if (/firefox\//i.test(value)) return 'Firefox';
  if (/chrome\//i.test(value)) return 'Chrome';
  if (/safari\//i.test(value)) return 'Safari';
  return null;
}

export function AccountSecurityDialog() {
  const t = useT();
  const open = useUiStore((state) => state.isAccountSecurityOpen);
  const close = useUiStore((state) => state.closeAccountSecurity);
  const logout = useAuthStore((state) => state.logout);
  const [sessions, setSessions] = useState<AuthSession[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [passkeys, setPasskeys] = useState<Array<{ id: string; name: string }>>([]);
  const [fingerprints, setFingerprints] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const currentDeviceId = useMemo(() => {
    if (!open) return null;
    try {
      return getActiveDevice().deviceId;
    } catch {
      return null;
    }
  }, [open]);

  const loadSecurityState = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [nextSessions, nextDevices] = await Promise.all([api.getSessions(), api.getDevices()]);
      setSessions(nextSessions);
      setDevices(nextDevices);
      setPasskeys(await api.securityRequest('/auth/passkeys'));
      setFingerprints(
        Object.fromEntries(
          await Promise.all(
            nextDevices.map(async (device) => [
              device.id,
              (await sha256(device.identityKey)).slice(0, 24).match(/.{4}/g)!.join(' '),
            ]),
          ),
        ),
      );
    } catch {
      setError(t('ログイン中の端末を読み込めませんでした。もう一度お試しください。'));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setPending(null);
      void loadSecurityState();
    }
  }, [loadSecurityState, open]);

  useEffect(() => {
    if (!open || isMutating) return;
    const socket = getSocket();
    const refresh = () => {
      void loadSecurityState();
    };
    socket?.on('device:registered', refresh);
    socket?.on('device:revoked', refresh);
    return () => {
      socket?.off('device:registered', refresh);
      socket?.off('device:revoked', refresh);
    };
  }, [open, isMutating, loadSecurityState]);

  const executePending = async () => {
    if (!pending || isMutating) return;
    setIsMutating(true);
    setError(null);
    try {
      if (pending.kind === 'approve') {
        const device = devices.find((d) => d.id === pending.id)!;
        await api.securityRequest(
          `/devices/${pending.id}/approve`,
          await deviceDecision(device, 'approve'),
        );
      } else if (pending.kind === 'session') await api.revokeSession(pending.id);
      else if (pending.kind === 'all-sessions') await api.revokeAllSessions();
      else await api.revokeDevice(pending.id);

      if (pending.requiresLogin) {
        await logout();
        close();
        return;
      }
      setPending(null);
      await loadSecurityState();
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.status === 403
          ? t('この操作を行う権限がありません。')
          : t('操作を完了できませんでした。もう一度お試しください。'),
      );
      setPending(null);
    } finally {
      setIsMutating(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => {
        if (!isMutating) close();
      }}
      title={t('ログイン中の端末')}
      description={t('不要なログインを終了したり、端末の登録を解除できます。')}
      size="lg"
    >
      <div className="space-y-6">
        {error && (
          <div
            role="alert"
            className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red"
          >
            {error}
          </div>
        )}
        {pending && (
          <section
            role="alertdialog"
            aria-label={t('操作の確認')}
            className="rounded border border-discord-red/60 bg-discord-red/10 p-4"
          >
            <h3 className="font-bold text-white">{t('この操作を確認してください')}</h3>
            <p className="mt-2 text-sm text-discord-text">{pending.label}</p>
            {pending.requiresLogin && (
              <p className="mt-2 text-sm font-medium text-discord-red">
                {t('この端末からログアウトするため、完了後に再ログインが必要です。')}
              </p>
            )}
            {pending.kind === 'device' && (
              <p className="mt-2 text-xs text-discord-muted">
                {t('解除した端末を再び使うには、ログインと端末の設定が必要です。')}
              </p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setPending(null)}
                disabled={isMutating}
                className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover"
              >
                {t('キャンセル')}
              </button>
              <button
                type="button"
                onClick={() => {
                  void executePending();
                }}
                disabled={isMutating}
                className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                {isMutating
                  ? t('処理中…')
                  : pending.kind === 'approve'
                    ? t('承認する')
                    : pending.kind === 'device'
                      ? t('登録を解除')
                      : t('ログアウト')}
              </button>
            </div>
          </section>
        )}

        {isLoading ? (
          <p className="py-8 text-center text-discord-muted">{t('読み込み中…')}</p>
        ) : (
          <>
            <section aria-labelledby="sessions-heading">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 id="sessions-heading" className="font-bold text-white">
                  {t('現在のログイン')}
                </h3>
                <button
                  type="button"
                  onClick={() =>
                    setPending({
                      kind: 'all-sessions',
                      label: t('すべての端末からログアウトします。'),
                      requiresLogin: true,
                    })
                  }
                  disabled={sessions.length === 0 || isMutating}
                  className="rounded border border-discord-red px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white disabled:opacity-40"
                >
                  {t('すべてログアウト')}
                </button>
              </div>
              <div className="space-y-2">
                {sessions.map((session) => (
                  <article
                    key={session.id}
                    className="flex items-start justify-between gap-4 rounded bg-discord-bg p-3"
                  >
                    <div className="min-w-0 text-sm">
                      <div className="font-medium text-discord-text">
                        {session.current ? t('この端末') : t('ログイン中')}
                        {session.current && (
                          <span className="ml-2 rounded bg-discord-green/20 px-2 py-0.5 text-xs text-discord-green">
                            {t('現在')}
                          </span>
                        )}
                      </div>
                      <p className="mt-1 break-words text-xs text-discord-muted">
                        {devices.find((device) => device.id === session.deviceId)?.name ||
                          sessionDescription(session)}
                      </p>
                      <p className="mt-1 text-xs text-discord-muted">
                        {t('ログイン: {start} / 自動ログアウト: {end}', { start: formatDate(session.createdAt), end: formatDate(session.expiresAt) })}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setPending({
                          kind: 'session',
                          id: session.id,
                          label: session.current
                            ? t('この端末からログアウトします。')
                            : t('{date} に開始したログインを終了します。', { date: formatDate(session.createdAt) }),
                          requiresLogin: session.current,
                        })
                      }
                      disabled={isMutating}
                      className="shrink-0 rounded px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white"
                    >
                      {t('ログアウト')}
                    </button>
                  </article>
                ))}
              </div>
            </section>

            <section aria-labelledby="devices-heading">
              <h3 id="devices-heading" className="mb-3 font-bold text-white">
                {t('登録済みの端末')}
              </h3>
              <div className="space-y-2">
                {devices.map((device) => {
                  const current = device.id === currentDeviceId;
                  return (
                    <article
                      key={device.id}
                      className="flex items-start justify-between gap-4 rounded bg-discord-bg p-3"
                    >
                      <div className="min-w-0 text-sm">
                        <div className="font-medium text-discord-text">
                          {device.name}
                          {current && (
                            <span className="ml-2 rounded bg-discord-green/20 px-2 py-0.5 text-xs text-discord-green">
                              {t('現在')}
                            </span>
                          )}
                        </div>
                        {device.approvedAt === null && (
                          <>
                            <p className="mt-1 text-sm text-discord-text">{t('承認待ち')}</p>
                            <p className="mt-1 select-all font-mono text-xs">
                              {t('確認コード: {code}', { code: fingerprints[device.id] ?? '' })}
                            </p>
                          </>
                        )}
                        <p className="mt-1 text-xs text-discord-muted">
                          {t('登録: {date}', { date: formatDate(device.createdAt) })}
                        </p>
                        <p className="text-xs text-discord-muted">
                          {t('最終利用: {date}', { date: device.lastActiveAt ? formatDate(device.lastActiveAt) : t('記録なし') })}
                        </p>
                      </div>
                      {device.approvedAt === null && (
                        <button
                          disabled={isMutating}
                          className="rounded bg-discord-accent px-3 py-2 text-sm text-white"
                          onClick={() =>
                            setPending({
                              kind: 'approve',
                              id: device.id,
                              label: t('「{name}」を承認すると、この端末で会話を読めるようになります。追加した端末の確認コードが {code} と一致していることを確認してください。', { name: device.name, code: fingerprints[device.id] ?? '' }),
                              requiresLogin: false,
                            })
                          }
                        >
                          {t('承認')}
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() =>
                          setPending({
                            kind: 'device',
                            id: device.id,
                            label: current
                              ? t('現在の端末「{name}」の登録を解除します。', { name: device.name })
                              : t('端末「{name}」の登録を解除します。', { name: device.name }),
                            requiresLogin: current,
                          })
                        }
                        disabled={isMutating}
                        className="shrink-0 rounded px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white"
                      >
                        {t('登録を解除')}
                      </button>
                    </article>
                  );
                })}
              </div>
            </section>
          </>
        )}
        <section className="space-y-3" aria-label={t('パスキー')}>
          <h3 className="font-bold text-white">{t('パスキー')}</h3>
          {passkeys.map((key) => (
            <div key={key.id} className="flex items-center justify-between text-sm">
              <span>{key.name}</span>
              <button
                disabled={isMutating || passkeys.length < 2}
                onClick={() => {
                  setIsMutating(true);
                  void api
                    .securityRequest(
                      `/auth/passkeys/${encodeURIComponent(key.id)}`,
                      undefined,
                      'DELETE',
                    )
                    .then(loadSecurityState)
                    .catch(() => setError(t('パスキーを削除できませんでした。')))
                    .finally(() => setIsMutating(false));
                }}
                className="text-discord-red disabled:opacity-40"
              >
                {t('削除')}
              </button>
            </div>
          ))}
          <button
            disabled={isMutating || !canUsePasskeys()}
            onClick={() => {
              setIsMutating(true);
              void registerPasskey(t('パスキー {number}', { number: passkeys.length + 1 }))
                .then(loadSecurityState)
                .catch(() => setError(t('パスキーを登録できませんでした。もう一度お試しください。')))
                .finally(() => setIsMutating(false));
            }}
            className="rounded bg-discord-accent px-3 py-2 text-white"
          >
            {t('パスキーを追加')}
          </button>
          {!canUsePasskeys() && (
            <p className="text-sm text-discord-muted">
              {t('パスキーの追加と本人確認は、対応するブラウザーでWeb版を開いて行ってください。')}
            </p>
          )}
        </section>
        {open && (
          <PasswordSettings
            hasPasskey={passkeys.length > 0}
            onChanged={() => {
              void loadSecurityState();
            }}
          />
        )}
        <DirectoryCheckpoint />
        <HistoryRecoverySettings />
        <DesktopSecuritySettings />
      </div>
    </Dialog>
  );
}
