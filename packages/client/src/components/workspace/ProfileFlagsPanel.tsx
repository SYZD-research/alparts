import { useCallback, useEffect, useState } from 'react';
import type { ProfileFlagEntry } from '@alparts/shared';
import { api } from '../../services/api';
import { formatDateTime } from '../../stores/date-format';
import { useUiStore } from '../../stores/ui.store';

const STATUS_LABELS: Record<ProfileFlagEntry['appealStatus'], string> = {
  none: '警告中',
  pending: '解除を依頼されています',
  denied: '解除の依頼を却下済み',
};

/** Profiles warned in this workspace, pending requests first. */
export function ProfileFlagsPanel({ workspaceId }: { workspaceId: string }) {
  const [flags, setFlags] = useState<ProfileFlagEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const openMemberProfile = useUiStore((state) => state.openMemberProfile);
  const closeWorkspaceManager = useUiStore((state) => state.closeWorkspaceManager);

  const load = useCallback(async () => {
    setError(null);
    try {
      const next = await api.listProfileFlags(workspaceId);
      setFlags([...next].sort((left, right) => Number(right.appealStatus === 'pending') - Number(left.appealStatus === 'pending')));
    } catch {
      setError('警告の一覧を読み込めませんでした。もう一度お試しください。');
    }
  }, [workspaceId]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p role="alert" className="text-sm text-discord-red">{error}</p>;
  if (!flags) return <p className="text-sm text-discord-muted">読み込み中…</p>;
  if (flags.length === 0) return <p className="text-sm text-discord-muted">警告を付けたプロフィールはありません。</p>;
  return (
    <ul className="space-y-2">
      {flags.map((flag) => (
        <li key={flag.userId} className="flex items-center justify-between gap-3 rounded bg-discord-bg/50 p-3 text-sm">
          <div className="min-w-0">
            <p className="truncate font-medium text-white">{flag.displayName}</p>
            <p className={flag.appealStatus === 'pending' ? 'text-discord-yellow' : 'text-discord-muted'}>
              {STATUS_LABELS[flag.appealStatus]} · {formatDateTime(flag.appealRequestedAt ?? flag.flaggedAt)}
            </p>
          </div>
          <button
            type="button"
            onClick={() => { closeWorkspaceManager(); openMemberProfile(workspaceId, flag.userId); }}
            className="shrink-0 rounded bg-discord-hover px-3 py-1.5 text-white"
          >
            確認する
          </button>
        </li>
      ))}
    </ul>
  );
}
