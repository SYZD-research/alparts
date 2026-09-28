import { useEffect, useState } from 'react';
import { connectSocket } from '../../services/socket';
import { getActiveDevice } from '../../services/crypto.service';
import { verifiedDirectory } from '../../services/directory.service';
import { sha256 } from '../../services/security-storage';
import { useAuthStore } from '../../stores/auth.store';
import { HistoryRecoverySettings } from './HistoryRecoverySettings';
export function DeviceApprovalPage({ onApproved }: { onApproved: () => void }) {
  const [fingerprint, setFingerprint] = useState('');
  const [error, setError] = useState(false);
  useEffect(() => {
    let stopped = false;
    const device = getActiveDevice();
    void sha256(device.identityKey).then((hash) => {
      if (!stopped) setFingerprint(hash.slice(0, 24).match(/.{4}/g)!.join(' '));
    });
    const refresh = async () => {
      try {
        const directory = await verifiedDirectory(device.userId);
        if (
          !stopped &&
          directory.devices[device.deviceId]?.approved &&
          !directory.devices[device.deviceId].revoked
        ) {
          device.approved = true;
          connectSocket();
          onApproved();
        }
      } catch {
        if (!stopped) setError(true);
      }
    };
    const timer = setInterval(() => {
      void refresh();
    }, 10_000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [onApproved]);
  return (
    <main className="min-h-screen bg-discord-bg p-6 text-discord-text">
      <div className="mx-auto max-w-xl space-y-6 rounded bg-discord-sidebar p-6">
        <h1 className="text-xl font-bold text-white">この端末の承認を待っています</h1>
        <p>
          以前から使っている端末で「ログイン中の端末」を開き、この端末を承認してください。表示される確認コードが一致していることを確認してください。
        </p>
        <p className="select-all rounded bg-discord-bg p-3 font-mono text-lg">{fingerprint}</p>
        {error && (
          <p role="alert">端末の情報を確認できませんでした。接続を確認してお試しください。</p>
        )}
        <HistoryRecoverySettings
          pending
          onRestored={() => {
            connectSocket();
            onApproved();
          }}
        />
        <button
          onClick={() => {
            void useAuthStore.getState().logout();
          }}
          className="text-discord-muted"
        >
          ログアウト
        </button>
      </div>
    </main>
  );
}
