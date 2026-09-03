import { useEffect, useRef, useState } from 'react';
import type { WorkspaceMember } from '@alparts/shared';
import { api, type EffectivePermissions } from '../../services/api';
import { managementErrorMessage, permissionLabel } from '../../stores/workspace-management-model';

interface EffectivePermissionsPanelProps {
  workspaceId: string;
  currentUserId: string;
  members: WorkspaceMember[];
  canInspectOthers: boolean;
}

export function EffectivePermissionsPanel({
  workspaceId,
  currentUserId,
  members,
  canInspectOthers,
}: EffectivePermissionsPanelProps) {
  const [selectedUserId, setSelectedUserId] = useState(currentUserId);
  const [evaluation, setEvaluation] = useState<EffectivePermissions | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);
  const visibleMembers = canInspectOthers
    ? members
    : members.filter((member) => member.userId === currentUserId);

  useEffect(() => {
    if (!canInspectOthers || !members.some((member) => member.userId === selectedUserId)) {
      setSelectedUserId(currentUserId);
    }
  }, [canInspectOthers, currentUserId, members, selectedUserId]);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    setLoading(true);
    setError(null);
    void api.getMemberPermissions(workspaceId, selectedUserId).then((result) => {
      if (generation === requestGeneration.current) setEvaluation(result);
    }).catch((loadError: unknown) => {
      if (generation === requestGeneration.current) {
        setEvaluation(null);
        setError(managementErrorMessage(loadError, '権限を読み込めませんでした'));
      }
    }).finally(() => {
      if (generation === requestGeneration.current) setLoading(false);
    });
    return () => { requestGeneration.current += 1; };
  }, [selectedUserId, workspaceId]);

  return (
    <section className="space-y-4" aria-labelledby="effective-permissions-title">
      <div>
        <h3 id="effective-permissions-title" className="font-semibold text-white">権限と付与理由</h3>
        <p className="mt-1 text-sm text-discord-muted">複数のロールを持つ場合の権限をまとめ、どのロールが各権限を許可しているかを表示します。</p>
      </div>
      <label className="block max-w-md text-sm text-discord-text">
        対象メンバー
        <select
          value={selectedUserId}
          onChange={(event) => setSelectedUserId(event.target.value)}
          disabled={!canInspectOthers}
          className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white disabled:opacity-70"
        >
          {visibleMembers.map((member) => (
            <option key={member.userId} value={member.userId}>{member.user.displayName}{member.userId === currentUserId ? '（自分）' : ''}</option>
          ))}
        </select>
      </label>
      {!canInspectOthers && <p className="text-xs text-discord-muted">他メンバーの権限理由を閲覧するには「ロールを管理」権限が必要です。</p>}
      {loading && <p role="status" className="text-sm text-discord-muted">権限を評価中…</p>}
      {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
      {evaluation && !loading && (
        <div className="space-y-4">
          <div className="rounded bg-discord-bg/50 p-3">
            <p className="text-xs font-bold uppercase tracking-wide text-discord-muted">割当ロール</p>
            <p className="mt-1 text-sm text-white">{evaluation.roles.map((role) => role.name).join('、') || 'なし'}</p>
          </div>
          <ul className="grid gap-2 md:grid-cols-2">
            {evaluation.permissionDetails.map((detail) => (
              <li key={detail.permission} className={`rounded border p-3 text-sm ${detail.allowed ? 'border-green-500/30 bg-green-500/5' : 'border-discord-hover bg-discord-bg/30'}`}>
                <p className={detail.allowed ? 'font-medium text-green-300' : 'text-discord-muted'}>
                  <span aria-hidden="true">{detail.allowed ? '✓' : '—'} </span>{permissionLabel(detail.permission)}
                </p>
                <p className="mt-1 text-xs text-discord-muted">
                  {detail.allowed
                    ? `理由: ${detail.reasons.map((reason) => reason.roleName).join('、') || '不明'}`
                    : 'この権限を付与するロールはありません。'}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
