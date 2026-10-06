import { useEffect, useMemo, useState, type FormEvent, type KeyboardEvent } from 'react';
import { type Permission, type WorkspaceMember } from '@alparts/shared';
import {
  api,
  type RoleChangePreview,
  type RolePreviewInput,
  type WorkspaceRole,
} from '../../services/api';
import {
  managementErrorMessage,
  permissionLabel,
  permissionMaskFromNames,
  permissionNamesFromMask,
  permissionOptions,
  roleMutationFailurePlan,
  roleProtection,
  summarizeRolePreview,
} from '../../stores/workspace-management-model';
import { useT, msg, type MessageKey } from '../../i18n';

interface RoleManagerProps {
  workspaceId: string;
  roles: WorkspaceRole[];
  members: WorkspaceMember[];
  canManage: boolean;
  loading: boolean;
  loadError: string | null;
  onReload: () => Promise<void>;
}

type PendingRoleAction =
  | {
    kind: 'update';
    role: WorkspaceRole;
    updates: { name: string; permissions: number; position: number };
    preview: RoleChangePreview;
  }
  | { kind: 'delete'; role: WorkspaceRole; preview: RoleChangePreview }
  | {
    kind: 'assignment';
    action: 'assign' | 'unassign';
    role: WorkspaceRole;
    member: WorkspaceMember;
    preview: RoleChangePreview;
  };

const actionTitles: Record<PendingRoleAction['kind'], MessageKey> = {
  update: msg('ロール変更を確認'),
  delete: msg('ロール削除を確認'),
  assignment: msg('ロール割当を確認'),
};

function previewInputForPending(pending: PendingRoleAction): RolePreviewInput {
  if (pending.kind === 'update') {
    return {
      operation: 'role.update',
      roleId: pending.role.id,
      permissions: pending.updates.permissions,
    };
  }
  if (pending.kind === 'delete') {
    return { operation: 'role.delete', roleId: pending.role.id };
  }
  return {
    operation: pending.action === 'assign' ? 'role.assign' : 'role.unassign',
    roleId: pending.role.id,
    userId: pending.member.userId,
  };
}

export function RoleManager({
  workspaceId,
  roles,
  members,
  canManage,
  loading,
  loadError,
  onReload,
}: RoleManagerProps) {
  const t = useT();
  const [selectedRoleId, setSelectedRoleId] = useState('');
  const [editName, setEditName] = useState('');
  const [editPosition, setEditPosition] = useState(0);
  const [editPermissions, setEditPermissions] = useState<Permission[]>([]);
  const [createName, setCreateName] = useState('');
  const [createPosition, setCreatePosition] = useState(1);
  const [createPermissions, setCreatePermissions] = useState<Permission[]>(['VIEW_CHANNELS']);
  const [assignmentUserId, setAssignmentUserId] = useState('');
  const [assignmentRoleId, setAssignmentRoleId] = useState('');
  const [pending, setPending] = useState<PendingRoleAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const selectedRole = roles.find((role) => role.id === selectedRoleId) || null;
  const assignmentRole = roles.find((role) => role.id === assignmentRoleId) || null;
  const assignmentMember = members.find((member) => member.userId === assignmentUserId) || null;
  const assignableRoles = roles.filter((role) => roleProtection(role) !== 'owner');

  useEffect(() => {
    if (!roles.some((role) => role.id === selectedRoleId)) setSelectedRoleId(roles[0]?.id || '');
    if (!assignableRoles.some((role) => role.id === assignmentRoleId)) setAssignmentRoleId(assignableRoles[0]?.id || '');
  }, [assignableRoles, assignmentRoleId, roles, selectedRoleId]);

  useEffect(() => {
    if (!members.some((member) => member.userId === assignmentUserId)) {
      setAssignmentUserId(members[0]?.userId || '');
    }
  }, [assignmentUserId, members]);

  useEffect(() => {
    if (!selectedRole) return;
    setEditName(selectedRole.name);
    setEditPosition(selectedRole.position);
    setEditPermissions(permissionNamesFromMask(selectedRole.permissionMask));
  }, [selectedRole]);

  const clearFeedback = () => {
    setError(null);
    setStatus(null);
  };

  const createRole = async (event: FormEvent) => {
    event.preventDefault();
    const name = createName.trim();
    if (!name || !Number.isSafeInteger(createPosition) || createPosition < 0) {
      setError(t('ロール名と0以上の階層位置を入力してください。'));
      return;
    }
    clearFeedback();
    setBusy(true);
    try {
      const created = await api.createRole(workspaceId, {
        name,
        permissions: permissionMaskFromNames(createPermissions),
        position: createPosition,
      });
      setCreateName('');
      setCreatePermissions(['VIEW_CHANNELS']);
      setSelectedRoleId(created.id);
      setStatus(t('ロール「{name}」を作成しました。', { name: created.name }));
      await onReload();
    } catch (createError) {
      setError(managementErrorMessage(createError, t('ロールを作成できませんでした')));
    } finally {
      setBusy(false);
    }
  };

  const previewUpdate = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedRole || roleProtection(selectedRole) === 'owner') return;
    const name = (selectedRole.standard ? selectedRole.name : editName).trim();
    if (!name || !Number.isSafeInteger(editPosition) || editPosition < 0) {
      setError(t('ロール名と0以上の階層位置を入力してください。'));
      return;
    }
    clearFeedback();
    setBusy(true);
    const updates = {
      name,
      permissions: permissionMaskFromNames(editPermissions),
      position: editPosition,
    };
    try {
      const preview = await api.previewRoleChange(workspaceId, {
        operation: 'role.update',
        roleId: selectedRole.id,
        permissions: updates.permissions,
      });
      setPending({ kind: 'update', role: selectedRole, updates, preview });
    } catch (previewError) {
      setError(managementErrorMessage(previewError, t('変更の影響を確認できませんでした')));
    } finally {
      setBusy(false);
    }
  };

  const previewDelete = async () => {
    if (!selectedRole || roleProtection(selectedRole)) return;
    clearFeedback();
    setBusy(true);
    try {
      const preview = await api.previewRoleChange(workspaceId, {
        operation: 'role.delete',
        roleId: selectedRole.id,
      });
      setPending({ kind: 'delete', role: selectedRole, preview });
    } catch (previewError) {
      setError(managementErrorMessage(previewError, t('削除の影響を確認できませんでした')));
    } finally {
      setBusy(false);
    }
  };

  const previewAssignment = async () => {
    if (!assignmentRole || !assignmentMember || roleProtection(assignmentRole) === 'owner') return;
    const assigned = assignmentMember.roles.some((role) => role.id === assignmentRole.id);
    const action = assigned ? 'unassign' : 'assign';
    clearFeedback();
    setBusy(true);
    try {
      const preview = await api.previewRoleChange(workspaceId, {
        operation: action === 'assign' ? 'role.assign' : 'role.unassign',
        roleId: assignmentRole.id,
        userId: assignmentMember.userId,
      });
      setPending({ kind: 'assignment', action, role: assignmentRole, member: assignmentMember, preview });
    } catch (previewError) {
      setError(managementErrorMessage(previewError, t('割当の影響を確認できませんでした')));
    } finally {
      setBusy(false);
    }
  };

  const confirmPending = async () => {
    if (!pending) return;
    const action = pending;
    setBusy(true);
    setError(null);
    try {
      if (action.kind === 'update') {
        await api.updateRole(workspaceId, action.role.id, action.updates, action.preview.authorizationRevision);
        setStatus(t('ロール「{name}」を変更しました。', { name: action.role.name }));
      } else if (action.kind === 'delete') {
        await api.deleteRole(workspaceId, action.role.id, action.preview.authorizationRevision);
        setSelectedRoleId('');
        setStatus(t('ロール「{name}」を削除しました。', { name: action.role.name }));
      } else if (action.action === 'assign') {
        await api.assignRole(workspaceId, action.member.userId, action.role.id, action.preview.authorizationRevision);
        setStatus(t('{member}に「{role}」を割り当てました。', { member: action.member.user.displayName, role: action.role.name }));
      } else {
        await api.unassignRole(workspaceId, action.member.userId, action.role.id, action.preview.authorizationRevision);
        setStatus(t('{member}から「{role}」を解除しました。', { member: action.member.user.displayName, role: action.role.name }));
      }
      setPending(null);
      await onReload();
    } catch (mutationError) {
      // Never allow confirmation of a preview after a failed mutation. A stale
      // authorization snapshot is refreshed, but still requires a new click.
      const failurePlan = roleMutationFailurePlan(mutationError);
      if (failurePlan.discardPreview) setPending(null);
      if (failurePlan.refreshPreview) {
        try {
          const preview = await api.previewRoleChange(workspaceId, previewInputForPending(action));
          setPending({ ...action, preview } as PendingRoleAction);
          setError(managementErrorMessage(mutationError, t('ロール操作を完了できませんでした')));
        } catch (refreshError) {
          setError(managementErrorMessage(refreshError, t('最新の確認内容を再取得できませんでした')));
        }
      } else {
        setError(managementErrorMessage(mutationError, t('ロール操作を完了できませんでした')));
      }
    } finally {
      setBusy(false);
    }
  };

  if (pending) {
    return (
      <RolePreviewConfirmation
        pending={pending}
        members={members}
        busy={busy}
        notice={error}
        onConfirm={() => void confirmPending()}
        onCancel={() => setPending(null)}
      />
    );
  }

  if (loading) return <p role="status" className="text-sm text-discord-muted">{t('ロールを読み込み中…')}</p>;
  if (loadError) return <p role="alert" className="text-sm text-discord-red">{loadError}</p>;

  if (!canManage) {
    return (
      <section className="space-y-3">
        <div>
          <h3 className="font-semibold text-white">{t('ロール一覧')}</h3>
          <p className="mt-1 text-sm text-discord-muted">{t('変更するには「ロールを管理」権限が必要です。')}</p>
        </div>
        <RoleList roles={roles} selectedRoleId="" onSelect={() => undefined} readOnly />
      </section>
    );
  }

  const selectedProtection = selectedRole ? roleProtection(selectedRole) : null;
  const assignmentExists = Boolean(assignmentMember && assignmentRole && assignmentMember.roles.some((role) => role.id === assignmentRole.id));

  return (
    <div className="space-y-7">
      {error && <p role="alert" className="rounded bg-discord-red/10 p-3 text-sm text-discord-red">{error}</p>}
      {status && <p role="status" className="rounded bg-green-500/10 p-3 text-sm text-green-300">{status}</p>}
      <div className="grid gap-5 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
        <section aria-labelledby="role-list-title">
          <h3 id="role-list-title" className="mb-2 font-semibold text-white">{t('ロール一覧')}</h3>
          <RoleList roles={roles} selectedRoleId={selectedRoleId} onSelect={setSelectedRoleId} />
        </section>

        <section aria-labelledby="role-edit-title">
          <h3 id="role-edit-title" className="mb-2 font-semibold text-white">{t('ロールを変更')}</h3>
          {selectedRole ? (
            <form onSubmit={previewUpdate} className="space-y-3 rounded bg-discord-bg/40 p-4">
              {selectedProtection && (
                <p className="rounded bg-yellow-500/10 p-2 text-xs text-yellow-200">
                  {selectedProtection === 'owner'
                    ? t('所有者ロールは変更、削除、割り当てができません。')
                    : t('標準ロールは名前変更と削除から保護されています。権限・位置の変更は影響を確認してから保存します。')}
                </p>
              )}
              <label className="block text-sm text-discord-text">
                {t('名前')}
                <input value={editName} onChange={(event) => setEditName(event.target.value)} disabled={Boolean(selectedProtection)} maxLength={100} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white disabled:opacity-60" />
              </label>
              <label className="block text-sm text-discord-text">
                {t('階層位置')}
                <input type="number" min={0} max={1_000_000} value={editPosition} onChange={(event) => setEditPosition(Number(event.target.value))} disabled={selectedProtection === 'owner'} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white disabled:opacity-60" />
              </label>
              <PermissionChecklist selected={editPermissions} onChange={setEditPermissions} disabled={selectedProtection === 'owner'} legend={t('ロールの権限')} />
              <div className="flex flex-wrap gap-2">
                <button type="submit" disabled={busy || selectedProtection === 'owner'} className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-50">{t('影響を確認')}</button>
                <button type="button" onClick={() => void previewDelete()} disabled={busy || Boolean(selectedProtection)} className="rounded px-4 py-2 text-sm text-discord-red hover:bg-discord-red/10 disabled:opacity-40">{t('削除の影響を確認')}</button>
              </div>
            </form>
          ) : <p className="text-sm text-discord-muted">{t('ロールを選択してください。')}</p>}
        </section>
      </div>

      <section aria-labelledby="role-create-title" className="rounded border border-discord-hover p-4">
        <h3 id="role-create-title" className="font-semibold text-white">{t('カスタムロールを作成')}</h3>
        <p className="mt-1 text-xs text-discord-muted">{t('「Owner」「Member」などの標準名は使用できません。自分より上の位置や、持っていない権限も指定できません。')}</p>
        <form onSubmit={createRole} className="mt-3 space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-sm text-discord-text">{t('名前')}<input value={createName} onChange={(event) => setCreateName(event.target.value)} maxLength={100} required className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white" /></label>
            <label className="text-sm text-discord-text">{t('階層位置')}<input type="number" min={0} max={1_000_000} value={createPosition} onChange={(event) => setCreatePosition(Number(event.target.value))} required className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white" /></label>
          </div>
          <PermissionChecklist selected={createPermissions} onChange={setCreatePermissions} legend={t('新しいロールの権限')} />
          <button type="submit" disabled={busy} className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-50">{t('作成')}</button>
        </form>
      </section>

      <section aria-labelledby="role-assignment-title" className="rounded border border-discord-hover p-4">
        <h3 id="role-assignment-title" className="font-semibold text-white">{t('メンバーへの割当・解除')}</h3>
        <p className="mt-1 text-xs text-discord-muted">{t('操作前に、影響を受ける人の権限やアクセス範囲の変化を確認します。')}</p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <label className="text-sm text-discord-text">{t('メンバー|single')}<select value={assignmentUserId} onChange={(event) => setAssignmentUserId(event.target.value)} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white">{members.map((member) => <option key={member.userId} value={member.userId}>{member.user.displayName}</option>)}</select></label>
          <label className="text-sm text-discord-text">{t('ロール|single')}<select value={assignmentRoleId} onChange={(event) => setAssignmentRoleId(event.target.value)} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white">{assignableRoles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}</select></label>
        </div>
        <button type="button" onClick={() => void previewAssignment()} disabled={busy || !assignmentMember || !assignmentRole} className={`mt-3 rounded px-4 py-2 text-sm text-white disabled:opacity-50 ${assignmentExists ? 'bg-discord-red' : 'bg-discord-accent'}`}>
          {assignmentExists ? t('解除の影響を確認') : t('割当の影響を確認')}
        </button>
      </section>
    </div>
  );
}

function RoleList({
  roles,
  selectedRoleId,
  onSelect,
  readOnly = false,
}: {
  roles: WorkspaceRole[];
  selectedRoleId: string;
  onSelect: (id: string) => void;
  readOnly?: boolean;
}) {
  const t = useT();
  if (roles.length === 0) return <p className="text-sm text-discord-muted">{t('ロールはありません。')}</p>;
  return (
    <ul className="space-y-1">
      {roles.map((role) => (
        <li key={role.id}>
          <button
            type="button"
            disabled={readOnly}
            onClick={() => onSelect(role.id)}
            className={`flex w-full items-center justify-between gap-2 rounded px-3 py-2 text-left text-sm ${selectedRoleId === role.id ? 'bg-discord-active text-white' : 'bg-discord-bg/40 text-discord-text hover:bg-discord-hover'} disabled:cursor-default`}
          >
            <span className="truncate">{role.name}</span>
            <span className="flex shrink-0 gap-1 text-xs text-discord-muted"><span>{t('位置 {position}', { position: role.position })}</span>{role.standard && <span className="rounded bg-yellow-500/10 px-1 text-yellow-200">{t('標準')}</span>}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function PermissionChecklist({
  selected,
  onChange,
  legend,
  disabled = false,
}: {
  selected: Permission[];
  onChange: (next: Permission[]) => void;
  legend: string;
  disabled?: boolean;
}) {
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  return (
    <fieldset disabled={disabled} className="rounded border border-discord-hover p-3 disabled:opacity-60">
      <legend className="px-1 text-sm text-discord-text">{legend}</legend>
      <div className="grid gap-2 sm:grid-cols-2">
        {permissionOptions.map((permission) => (
          <label key={permission.name} className="flex items-start gap-2 text-xs text-discord-text">
            <input
              type="checkbox"
              checked={selectedSet.has(permission.name)}
              onChange={(event) => onChange(event.target.checked
                ? [...selected, permission.name]
                : selected.filter((name) => name !== permission.name))}
              className="mt-0.5"
            />
            <span>{permission.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function RolePreviewConfirmation({
  pending,
  members,
  busy,
  notice,
  onConfirm,
  onCancel,
}: {
  pending: PendingRoleAction;
  members: WorkspaceMember[];
  busy: boolean;
  notice: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const summary = summarizeRolePreview(pending.preview);
  const title = pending.kind === 'assignment'
    ? pending.action === 'assign'
      ? t('{member}の「{role}」を割当', { member: pending.member.user.displayName, role: pending.role.name })
      : t('{member}の「{role}」を解除', { member: pending.member.user.displayName, role: pending.role.name })
    : pending.kind === 'delete'
      ? t('「{role}」を削除', { role: pending.role.name })
      : t('「{role}」を変更', { role: pending.role.name });

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    onCancel();
  };

  return (
    <section
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="role-preview-title"
      aria-describedby="role-preview-description"
      onKeyDown={onKeyDown}
      className="space-y-4 rounded border border-yellow-500/50 bg-discord-bg/50 p-5"
    >
      <div>
        <p className="text-xs font-bold uppercase tracking-wide text-yellow-300">{t(actionTitles[pending.kind])}</p>
        <h3 id="role-preview-title" className="mt-1 text-lg font-semibold text-white">{title}</h3>
        <p id="role-preview-description" className="mt-1 text-sm text-discord-muted">{t('この変更の影響を確認してください。')}</p>
      </div>
      {notice && <p role="alert" className="rounded bg-yellow-500/10 p-3 text-sm text-yellow-200">{notice}</p>}
      <dl className="grid gap-2 text-sm sm:grid-cols-3">
        <PreviewMetric label={t('影響を受けるユーザー')} value={summary.affectedUsers} />
        <PreviewMetric label={t('失う権限（延べ）')} value={summary.lostPermissions} danger={summary.lostPermissions > 0} />
        <PreviewMetric label={t('得る権限（延べ）')} value={summary.gainedPermissions} />
        <PreviewMetric label={t('閲覧できなくなる人')} value={summary.lostAccessUsers} danger={summary.lostAccessUsers > 0} />
        <PreviewMetric label={t('閲覧できるようになる人')} value={summary.gainedAccessUsers} />
        <PreviewMetric label={t('一時的な送信制限')} value={summary.requiresKeyRotation ? t('可能性あり') : t('なし')} danger={summary.requiresKeyRotation} />
      </dl>
      {pending.preview.affectedMembers.length > 0 && (
        <ul className="max-h-48 space-y-2 overflow-y-auto" aria-label={t('ユーザーごとの権限の変化')}>
          {pending.preview.affectedMembers.map((affected) => {
            const memberName = members.find((member) => member.userId === affected.userId)?.user.displayName || t('不明なメンバー');
            return (
              <li key={affected.userId} className="rounded bg-discord-sidebar p-3 text-sm">
                <p className="font-medium text-white">{memberName}</p>
                <p className="mt-1 text-xs text-green-300">{t('追加される権限: {permissions}', { permissions: affected.gained.map(permissionLabel).join(t('、')) || t('なし') })}</p>
                <p className="mt-1 text-xs text-discord-red">{t('失う権限: {permissions}', { permissions: affected.lost.map(permissionLabel).join(t('、')) || t('なし') })}</p>
              </li>
            );
          })}
        </ul>
      )}
      {summary.requiresKeyRotation && <p role="alert" className="rounded bg-discord-red/10 p-3 text-sm text-discord-red">{t('影響するチャンネルでは、変更後しばらくメッセージを送信できない場合があります。')}</p>}
      <div className="flex flex-wrap justify-end gap-2">
        <button autoFocus type="button" onClick={onCancel} disabled={busy} className="rounded px-4 py-2 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">{t('キャンセル')}</button>
        <button type="button" onClick={onConfirm} disabled={busy} className={`rounded px-4 py-2 text-sm font-medium text-white disabled:opacity-50 ${pending.kind === 'delete' || pending.kind === 'assignment' && pending.action === 'unassign' ? 'bg-discord-red' : 'bg-discord-accent'}`}>
          {busy ? t('実行中…') : t('この内容で保存')}
        </button>
      </div>
    </section>
  );
}

function PreviewMetric({ label, value, danger = false }: { label: string; value: number | string; danger?: boolean }) {
  return (
    <div className="rounded bg-discord-sidebar p-3">
      <dt className="text-xs text-discord-muted">{label}</dt>
      <dd className={`mt-1 font-semibold ${danger ? 'text-discord-red' : 'text-white'}`}>{value}</dd>
    </div>
  );
}
