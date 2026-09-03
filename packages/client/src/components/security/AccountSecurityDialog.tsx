import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Device } from '@alparts/shared';
import { ApiError, api, type AuthSession } from '../../services/api';
import { getActiveDevice } from '../../services/crypto.service';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { Dialog } from '../ui/Dialog';

type PendingAction =
  | { kind: 'session'; id: string; label: string; requiresLogin: boolean }
  | { kind: 'all-sessions'; label: string; requiresLogin: true }
  | { kind: 'device'; id: string; label: string; requiresLogin: boolean };

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '不明' : date.toLocaleString('ja-JP');
}

function sessionDescription(session: AuthSession): string {
  const platform = friendlyPlatform(session.deviceInfo?.platform);
  const browser = friendlyBrowser(session.deviceInfo?.browser);
  return [platform, browser].filter(Boolean).join('・') || '名前のない端末';
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
  const open = useUiStore((state) => state.isAccountSecurityOpen);
  const close = useUiStore((state) => state.closeAccountSecurity);
  const logout = useAuthStore((state) => state.logout);
  const [sessions, setSessions] = useState<AuthSession[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const currentDeviceId = useMemo(() => {
    if (!open) return null;
    try { return getActiveDevice().deviceId; } catch { return null; }
  }, [open]);

  const loadSecurityState = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [nextSessions, nextDevices] = await Promise.all([api.getSessions(), api.getDevices()]);
      setSessions(nextSessions);
      setDevices(nextDevices);
    } catch {
      setError('ログイン中の端末を読み込めませんでした。もう一度お試しください。');
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

  const executePending = async () => {
    if (!pending || isMutating) return;
    setIsMutating(true);
    setError(null);
    try {
      if (pending.kind === 'session') await api.revokeSession(pending.id);
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
      setError(caught instanceof ApiError && caught.status === 403
        ? 'この操作を行う権限がありません。'
        : '操作を完了できませんでした。もう一度お試しください。');
      setPending(null);
    } finally {
      setIsMutating(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => { if (!isMutating) close(); }}
      title="ログイン中の端末"
      description="不要なログインを終了したり、端末の登録を解除できます。"
      size="lg"
    >
      <div className="space-y-6">
        {error && <div role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{error}</div>}
        {pending && (
          <section role="alertdialog" aria-label="操作の確認" className="rounded border border-discord-red/60 bg-discord-red/10 p-4">
            <h3 className="font-bold text-white">この操作を確認してください</h3>
            <p className="mt-2 text-sm text-discord-text">{pending.label}</p>
            {pending.requiresLogin && (
              <p className="mt-2 text-sm font-medium text-discord-red">この端末からログアウトするため、完了後に再ログインが必要です。</p>
            )}
            {pending.kind === 'device' && (
              <p className="mt-2 text-xs text-discord-muted">解除した端末を再び使うには、ログインと端末の設定が必要です。</p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <button type="button" onClick={() => setPending(null)} disabled={isMutating} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">キャンセル</button>
              <button type="button" onClick={() => { void executePending(); }} disabled={isMutating} className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white disabled:opacity-50">
                {isMutating ? '処理中…' : pending.kind === 'device' ? '登録を解除' : 'ログアウト'}
              </button>
            </div>
          </section>
        )}

        {isLoading ? (
          <p className="py-8 text-center text-discord-muted">読み込み中…</p>
        ) : (
          <>
            <section aria-labelledby="sessions-heading">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 id="sessions-heading" className="font-bold text-white">現在のログイン</h3>
                <button
                  type="button"
                  onClick={() => setPending({ kind: 'all-sessions', label: 'すべての端末からログアウトします。', requiresLogin: true })}
                  disabled={sessions.length === 0 || isMutating}
                  className="rounded border border-discord-red px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white disabled:opacity-40"
                >
                  すべてログアウト
                </button>
              </div>
              <div className="space-y-2">
                {sessions.map((session) => (
                  <article key={session.id} className="flex items-start justify-between gap-4 rounded bg-discord-bg p-3">
                    <div className="min-w-0 text-sm">
                      <div className="font-medium text-discord-text">
                        {session.current ? 'この端末' : 'ログイン中'}
                        {session.current && <span className="ml-2 rounded bg-discord-green/20 px-2 py-0.5 text-xs text-discord-green">現在</span>}
                      </div>
                      <p className="mt-1 break-words text-xs text-discord-muted">
                        {devices.find((device) => device.id === session.deviceId)?.name || sessionDescription(session)}
                      </p>
                      <p className="mt-1 text-xs text-discord-muted">ログイン: {formatDate(session.createdAt)} / 自動ログアウト: {formatDate(session.expiresAt)}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setPending({
                        kind: 'session',
                        id: session.id,
                        label: session.current ? 'この端末からログアウトします。' : `${formatDate(session.createdAt)} に開始したログインを終了します。`,
                        requiresLogin: session.current,
                      })}
                      disabled={isMutating}
                      className="shrink-0 rounded px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white"
                    >
                      ログアウト
                    </button>
                  </article>
                ))}
              </div>
            </section>

            <section aria-labelledby="devices-heading">
              <h3 id="devices-heading" className="mb-3 font-bold text-white">登録済みの端末</h3>
              <div className="space-y-2">
                {devices.map((device) => {
                  const current = device.id === currentDeviceId;
                  return (
                    <article key={device.id} className="flex items-start justify-between gap-4 rounded bg-discord-bg p-3">
                      <div className="min-w-0 text-sm">
                        <div className="font-medium text-discord-text">
                          {device.name}
                          {current && <span className="ml-2 rounded bg-discord-green/20 px-2 py-0.5 text-xs text-discord-green">現在</span>}
                        </div>
                        <p className="mt-1 text-xs text-discord-muted">登録: {formatDate(device.createdAt)}</p>
                        <p className="text-xs text-discord-muted">最終利用: {device.lastActiveAt ? formatDate(device.lastActiveAt) : '記録なし'}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setPending({
                          kind: 'device',
                          id: device.id,
                          label: current ? `現在の端末「${device.name}」の登録を解除します。` : `端末「${device.name}」の登録を解除します。`,
                          requiresLogin: current,
                        })}
                        disabled={isMutating}
                        className="shrink-0 rounded px-3 py-1.5 text-xs text-discord-red hover:bg-discord-red hover:text-white"
                      >
                        登録を解除
                      </button>
                    </article>
                  );
                })}
              </div>
            </section>
          </>
        )}
      </div>
    </Dialog>
  );
}
