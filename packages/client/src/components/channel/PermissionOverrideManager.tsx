import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { Category, Channel, WorkspaceMember } from '@alparts/shared';
import {
  ApiError,
  api,
  type ChannelEffectivePermissions,
  type PermissionOverride,
  type PermissionOverridePreview,
  type PermissionOverridePreviewInput,
  type PermissionOverrideTarget,
  type WorkspaceRole,
} from '../../services/api';
import {
  channelScopedPermissions,
  formatChannelPermissionReason,
  overrideDeleteInputFromPreview,
  overrideMutationFailurePlan,
  permissionOverridePreviewMatches,
  overridePermissionState,
  overrideWriteInputFromPreview,
  setOverridePermissionState,
  summarizeOverridePreview,
  validateOverrideMasks,
  type OverridePermissionState,
} from '../../stores/permission-override-model';
import { permissionLabel, roleProtection } from '../../stores/workspace-management-model';

interface Props {
  workspaceId: string;
  channels: Channel[];
  categories: Category[];
  members: WorkspaceMember[];
  onChanged: () => Promise<unknown>;
}

interface PendingOverrideAction {
  target: PermissionOverrideTarget;
  targetId: string;
  targetLabel: string;
  role: WorkspaceRole;
  input: PermissionOverridePreviewInput;
  preview: PermissionOverridePreview;
}

function overrideErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'この対象の権限を管理できません。状態は変更されていません。';
    if (error.status === 404) return '対象、ロール、または設定が現在の閲覧範囲にありません。';
    if (error.status === 409 && (error.code === 'STALE_PREVIEW' || error.code === 'STALE_OVERRIDE')) {
      return '確認中に権限状態が変更されました。最新の影響を確認し、もう一度保存してください。';
    }
    if (error.status === 409) return 'この設定は別の操作と競合しました。一覧を再読み込みしてください。';
    if (error.status === 400) return '許可・拒否する権限の範囲を確認してください。';
  }
  return fallback;
}

export function PermissionOverrideManager({ workspaceId, channels, categories, members, onChanged }: Props) {
  const [target, setTarget] = useState<PermissionOverrideTarget>('channel');
  const [targetId, setTargetId] = useState('');
  const [roles, setRoles] = useState<WorkspaceRole[]>([]);
  const [selectedRoleId, setSelectedRoleId] = useState('');
  const [overrides, setOverrides] = useState<PermissionOverride[]>([]);
  const [allowMask, setAllowMask] = useState(0);
  const [denyMask, setDenyMask] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingOverrideAction | null>(null);
  const [effectiveChannelId, setEffectiveChannelId] = useState('');
  const [effectiveUserId, setEffectiveUserId] = useState('');
  const [effective, setEffective] = useState<ChannelEffectivePermissions | null>(null);
  const [effectiveError, setEffectiveError] = useState<string | null>(null);
  const [effectiveLoading, setEffectiveLoading] = useState(false);
  const [effectiveRefresh, setEffectiveRefresh] = useState(0);
  const roleRequest = useRef(0);
  const overrideRequest = useRef(0);
  const effectiveRequest = useRef(0);

  const manageableChannels = useMemo(
    () => channels.filter((channel) => channel.type !== 'dm'),
    [channels],
  );
  const targetOptions = target === 'channel' ? manageableChannels : categories;
  const selectableRoles = useMemo(
    () => roles.filter((role) => roleProtection(role) !== 'owner'),
    [roles],
  );
  const selectedRole = roles.find((role) => role.id === selectedRoleId) || null;
  const selectedOverride = overrides.find((override) => override.roleId === selectedRoleId) || null;
  const targetLabel = targetOptions.find((option) => option.id === targetId)?.name || '対象';

  useEffect(() => {
    const request = ++roleRequest.current;
    setRoles([]);
    setError(null);
    void api.getRoles(workspaceId).then((next) => {
      if (request === roleRequest.current) setRoles(next);
    }).catch((caught: unknown) => {
      if (request === roleRequest.current) setError(overrideErrorMessage(caught, 'ロールを読み込めませんでした'));
    });
    return () => { roleRequest.current += 1; };
  }, [workspaceId]);

  useEffect(() => {
    if (target === 'channel' && manageableChannels.length === 0 && categories.length > 0) {
      setTarget('category');
      return;
    }
    if (!targetOptions.some((option) => option.id === targetId)) setTargetId(targetOptions[0]?.id || '');
  }, [categories.length, manageableChannels.length, target, targetId, targetOptions]);

  useEffect(() => {
    if (!selectableRoles.some((role) => role.id === selectedRoleId)) {
      setSelectedRoleId(selectableRoles[0]?.id || '');
    }
  }, [selectableRoles, selectedRoleId]);

  const loadOverrides = useCallback(async (
    requestedTarget: PermissionOverrideTarget,
    requestedTargetId: string,
  ): Promise<PermissionOverride[]> => {
    if (!requestedTargetId) {
      setOverrides([]);
      return [];
    }
    const request = ++overrideRequest.current;
    setLoading(true);
    setError(null);
    try {
      const next = await api.getPermissionOverrides(requestedTarget, workspaceId, requestedTargetId);
      if (request === overrideRequest.current) setOverrides(next);
      return next;
    } catch (caught) {
      if (request === overrideRequest.current) {
        setOverrides([]);
        setError(overrideErrorMessage(caught, '設定一覧を読み込めませんでした'));
      }
      throw caught;
    } finally {
      if (request === overrideRequest.current) setLoading(false);
    }
  }, [workspaceId]);

  useEffect(() => {
    setOverrides([]);
    setPending(null);
    setNotice(null);
    if (targetId) void loadOverrides(target, targetId).catch(() => undefined);
    return () => { overrideRequest.current += 1; };
  }, [loadOverrides, target, targetId]);

  useEffect(() => {
    setAllowMask(selectedOverride?.allowMask || 0);
    setDenyMask(selectedOverride?.denyMask || 0);
  }, [selectedOverride?.allowMask, selectedOverride?.denyMask, selectedRoleId, targetId]);

  useEffect(() => {
    if (!manageableChannels.some((channel) => channel.id === effectiveChannelId)) {
      setEffectiveChannelId(manageableChannels[0]?.id || '');
    }
    if (!members.some((member) => member.userId === effectiveUserId)) {
      setEffectiveUserId(members[0]?.userId || '');
    }
  }, [effectiveChannelId, effectiveUserId, manageableChannels, members]);

  useEffect(() => {
    if (!effectiveChannelId || !effectiveUserId) {
      setEffective(null);
      return;
    }
    const request = ++effectiveRequest.current;
    setEffectiveLoading(true);
    setEffectiveError(null);
    void api.getEffectiveChannelPermissions(workspaceId, effectiveChannelId, effectiveUserId).then((result) => {
      if (request === effectiveRequest.current) setEffective(result);
    }).catch((caught: unknown) => {
      if (request === effectiveRequest.current) {
        setEffective(null);
        setEffectiveError(overrideErrorMessage(caught, '実際のチャンネル権限を読み込めませんでした'));
      }
    }).finally(() => {
      if (request === effectiveRequest.current) setEffectiveLoading(false);
    });
    return () => { effectiveRequest.current += 1; };
  }, [effectiveChannelId, effectiveRefresh, effectiveUserId, workspaceId]);

  const updatePermission = (permission: number, next: OverridePermissionState) => {
    if (next === 'conflict') return;
    const masks = setOverridePermissionState(allowMask, denyMask, permission, next);
    setAllowMask(masks.allowMask);
    setDenyMask(masks.denyMask);
    setError(null);
    setNotice(null);
  };

  const previewAction = async (input: PermissionOverridePreviewInput) => {
    if (!targetId || !selectedRole || busy) return;
    const maskError = input.operation === 'upsert' ? validateOverrideMasks(input.allowMask, input.denyMask) : null;
    if (maskError) {
      setError(maskError);
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const preview = await api.previewPermissionOverride(target, workspaceId, targetId, input);
      if (!permissionOverridePreviewMatches(preview, {
        target,
        workspaceId,
        targetId,
        roleId: selectedRole.id,
        operation: input.operation,
      })) {
        throw new Error('確認対象が一致しません');
      }
      setPending({ target, targetId, targetLabel, role: selectedRole, input, preview });
    } catch (caught) {
      setError(overrideErrorMessage(caught, '変更の影響を確認できませんでした'));
    } finally {
      setBusy(false);
    }
  };

  const confirmPending = async () => {
    if (!pending || busy) return;
    const action = pending;
    setBusy(true);
    setError(null);
    try {
      if (action.input.operation === 'upsert') {
        await api.upsertPermissionOverride(
          action.target,
          workspaceId,
          action.targetId,
          action.role.id,
          overrideWriteInputFromPreview(action.preview, action.input.allowMask, action.input.denyMask),
        );
      } else {
        await api.deletePermissionOverride(
          action.target,
          workspaceId,
          action.targetId,
          action.role.id,
          overrideDeleteInputFromPreview(action.preview),
        );
      }
      setPending(null);
      setNotice(action.input.operation === 'delete'
        ? `ロール「${action.role.name}」の権限設定を削除しました。`
        : `ロール「${action.role.name}」の権限設定を保存しました。`);
      await Promise.allSettled([
        loadOverrides(action.target, action.targetId),
        onChanged(),
      ]);
      setEffectiveRefresh((value) => value + 1);
    } catch (caught) {
      const plan = overrideMutationFailurePlan(caught);
      if (plan.discardPreview) setPending(null);
      if (plan.refreshPreview) {
        try {
          await loadOverrides(action.target, action.targetId);
          const preview = await api.previewPermissionOverride(action.target, workspaceId, action.targetId, action.input);
          if (!permissionOverridePreviewMatches(preview, {
            target: action.target,
            workspaceId,
            targetId: action.targetId,
            roleId: action.role.id,
            operation: action.input.operation,
          })) throw new Error('再取得した確認内容が一致しません');
          setPending({ ...action, preview });
          setError(overrideErrorMessage(caught, '権限設定の確認内容を最新に更新しました'));
        } catch (refreshError) {
          setError(overrideErrorMessage(refreshError, '最新の確認内容を再取得できませんでした'));
        }
      } else {
        setError(overrideErrorMessage(caught, '権限設定を変更できませんでした'));
      }
    } finally {
      setBusy(false);
    }
  };

  if (pending) {
    return (
      <OverrideConfirmation
        pending={pending}
        members={members}
        channels={manageableChannels}
        busy={busy}
        notice={error}
        onConfirm={() => void confirmPending()}
        onCancel={() => { setPending(null); setError(null); }}
      />
    );
  }

  const hasConflict = validateOverrideMasks(allowMask, denyMask) !== null;
  const unchanged = Boolean(selectedOverride
    && selectedOverride.allowMask === allowMask
    && selectedOverride.denyMask === denyMask);

  return (
    <div className="space-y-7">
      <section aria-labelledby="override-editor-title" className="space-y-4">
        <div>
          <h3 id="override-editor-title" className="font-semibold text-white">ロール別チャンネル権限</h3>
          <p className="mt-1 text-sm text-discord-muted">許可・拒否はワークスペースロールの上にカテゴリー、チャンネルの順で適用され、同じ階層では拒否が優先されます。</p>
        </div>

        {error && <p role="alert" className="rounded bg-discord-red/15 p-3 text-sm text-discord-red">{error}</p>}
        {notice && <p role="status" className="rounded bg-discord-green/15 p-3 text-sm text-discord-green">{notice}</p>}

        <div className="grid gap-3 md:grid-cols-3">
          <label className="text-sm text-discord-text">対象の種類
            <select
              value={target}
              onChange={(event) => { setTarget(event.target.value as PermissionOverrideTarget); setTargetId(''); }}
              className="mt-1 w-full rounded bg-discord-input px-3 py-2"
            >
              <option value="channel">チャンネル</option>
              <option value="category">カテゴリー</option>
            </select>
          </label>
          <label className="text-sm text-discord-text">対象
            <select value={targetId} onChange={(event) => setTargetId(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
              {targetOptions.map((option) => <option key={option.id} value={option.id}>{option.name}</option>)}
            </select>
          </label>
          <label className="text-sm text-discord-text">ロール
            <select value={selectedRoleId} onChange={(event) => setSelectedRoleId(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
              {selectableRoles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}
            </select>
          </label>
        </div>

        {roles.some((role) => roleProtection(role) === 'owner') && (
          <p className="text-xs text-discord-muted">所有者ロールは変更できません。</p>
        )}

        {!targetId || !selectedRole ? (
          <p role="status" className="rounded bg-discord-bg p-3 text-sm text-discord-muted">管理できる対象またはロールがありません。</p>
        ) : loading ? (
          <p role="status" className="text-sm text-discord-muted">設定を読み込み中…</p>
        ) : (
          <>
            <fieldset className="rounded border border-discord-hover p-4">
              <legend className="px-1 text-sm text-discord-text">各権限の設定</legend>
              <div className="grid gap-3 md:grid-cols-2">
                {channelScopedPermissions.map((permission) => {
                  const state = overridePermissionState(allowMask, denyMask, permission.value);
                  return (
                    <label key={permission.name} className="flex items-center justify-between gap-3 rounded bg-discord-bg/60 px-3 py-2 text-sm text-discord-text">
                      <span>{permissionLabel(permission.name)}</span>
                      <select
                        aria-label={`${permissionLabel(permission.name)}の設定`}
                        value={state}
                        onChange={(event) => updatePermission(permission.value, event.target.value as OverridePermissionState)}
                        className="rounded bg-discord-input px-2 py-1 text-xs"
                      >
                        <option value="inherit">継承</option>
                        <option value="allow">許可</option>
                        <option value="deny">拒否</option>
                        {state === 'conflict' && <option value="conflict" disabled>競合（要解消）</option>}
                      </select>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-discord-muted">
                {selectedOverride ? '保存済み' : 'このロールの設定はまだありません。'}
              </p>
              <div className="flex gap-2">
                {selectedOverride && (
                  <button
                    type="button"
                    onClick={() => void previewAction({ operation: 'delete', roleId: selectedRole.id })}
                    disabled={busy}
                    className="rounded px-3 py-2 text-sm text-discord-red hover:bg-discord-red/10 disabled:opacity-50"
                  >削除の影響を確認</button>
                )}
                <button
                  type="button"
                  onClick={() => void previewAction({ operation: 'upsert', roleId: selectedRole.id, allowMask, denyMask })}
                  disabled={busy || hasConflict || unchanged}
                  className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-50"
                >{busy ? '確認中…' : '変更の影響を確認'}</button>
              </div>
            </div>
          </>
        )}

        {overrides.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-white">保存済みの設定一覧</h4>
            <ul className="mt-2 grid gap-2 md:grid-cols-2">
              {overrides.map((override) => {
                const role = roles.find((candidate) => candidate.id === override.roleId);
                return (
                  <li key={override.roleId}>
                    <button
                      type="button"
                      onClick={() => setSelectedRoleId(override.roleId)}
                      className="flex w-full items-center justify-between rounded bg-discord-bg/60 px-3 py-2 text-left text-xs text-discord-text hover:bg-discord-hover"
                    >
                      <span>{role?.name || '不明なロール'}</span>
                      <span className="text-discord-muted">許可 {bitCount(override.allowMask)} / 拒否 {bitCount(override.denyMask)}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </section>

      <EffectiveChannelPermissions
        channels={manageableChannels}
        members={members}
        channelId={effectiveChannelId}
        userId={effectiveUserId}
        evaluation={effective}
        loading={effectiveLoading}
        error={effectiveError}
        onChannelChange={setEffectiveChannelId}
        onUserChange={setEffectiveUserId}
      />
    </div>
  );
}

function OverrideConfirmation({ pending, members, channels, busy, notice, onConfirm, onCancel }: {
  pending: PendingOverrideAction;
  members: WorkspaceMember[];
  channels: Channel[];
  busy: boolean;
  notice: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const summary = summarizeOverridePreview(pending.preview);
  const before = pending.preview.before;
  const after = pending.preview.after;
  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    onCancel();
  };
  const namesForMask = (mask: number) => channelScopedPermissions
    .filter((permission) => (mask & permission.value) === permission.value)
    .map((permission) => permissionLabel(permission.name)).join('、') || 'なし';

  return (
    <section role="alertdialog" aria-modal="true" aria-labelledby="override-preview-title" onKeyDown={onKeyDown} className="space-y-4 rounded border border-yellow-500/50 bg-discord-bg/50 p-5">
      <div>
        <p className="text-xs font-bold uppercase tracking-wide text-yellow-300">権限設定の確認</p>
        <h3 id="override-preview-title" className="mt-1 text-lg font-semibold text-white">
          {pending.target === 'category' ? 'カテゴリー' : 'チャンネル'}「{pending.targetLabel}」 / {pending.role.name}
        </h3>
        <p className="mt-1 text-sm text-discord-muted">保存時に他の管理者の変更と競合した場合は、最新の状態を確認してからやり直します。</p>
      </div>
      {notice && <p role="alert" className="rounded bg-yellow-500/10 p-3 text-sm text-yellow-200">{notice}</p>}
      <dl className="grid gap-2 text-sm sm:grid-cols-4">
        <PreviewMetric label="影響を受けるチャンネル" value={summary.affectedChannels} />
        <PreviewMetric label="閲覧できなくなる人" value={summary.losingUsers} danger={summary.losingUsers > 0} />
        <PreviewMetric label="閲覧できるようになる人" value={summary.gainingUsers} />
        <PreviewMetric label="一時的に送信できない可能性があるチャンネル" value={summary.rotationChannels} danger={summary.rotationChannels > 0} />
      </dl>
      <div className="grid gap-3 text-xs md:grid-cols-2">
        <div className="rounded bg-discord-sidebar p-3 text-discord-muted">
          <p className="font-medium text-white">変更前</p>
          <p className="mt-2">許可: {namesForMask(before?.allowMask || 0)}</p>
          <p className="mt-1">拒否: {namesForMask(before?.denyMask || 0)}</p>
        </div>
        <div className="rounded bg-discord-sidebar p-3 text-discord-muted">
          <p className="font-medium text-white">変更後</p>
          <p className="mt-2">許可: {namesForMask(after?.allowMask || 0)}</p>
          <p className="mt-1">拒否: {namesForMask(after?.denyMask || 0)}</p>
          {pending.input.operation === 'delete' && <p className="mt-1 text-yellow-200">この設定を削除し、上位の設定を引き継ぎます。</p>}
        </div>
      </div>
      {pending.preview.roomEffects.length > 0 && (
        <ul className="max-h-52 space-y-2 overflow-y-auto" aria-label="チャンネルごとの閲覧者への影響">
          {pending.preview.roomEffects.map((effect) => (
            <li key={effect.channelId} className="rounded bg-discord-sidebar p-3 text-xs text-discord-muted">
              <p className="font-medium text-white">{channels.find((channel) => channel.id === effect.channelId)?.name || '表示できないチャンネル'}</p>
              <p className="mt-1 text-discord-red">閲覧できなくなる人: {memberNames(effect.lostUserIds, members)}</p>
              <p className="mt-1 text-green-300">閲覧できるようになる人: {memberNames(effect.gainedUserIds, members)}</p>
              {effect.rotationRequired && <p className="mt-1 text-yellow-200">変更後、しばらくメッセージを送信できない場合があります。</p>}
            </li>
          ))}
        </ul>
      )}
      <div className="flex justify-end gap-2">
        <button autoFocus type="button" onClick={onCancel} disabled={busy} className="rounded px-4 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">キャンセル</button>
        <button type="button" onClick={onConfirm} disabled={busy} className={`rounded px-4 py-2 text-sm text-white disabled:opacity-50 ${pending.input.operation === 'delete' || summary.losingUsers > 0 ? 'bg-discord-red' : 'bg-discord-accent'}`}>
          {busy ? '実行中…' : 'この内容で保存'}
        </button>
      </div>
    </section>
  );
}

function EffectiveChannelPermissions({ channels, members, channelId, userId, evaluation, loading, error, onChannelChange, onUserChange }: {
  channels: Channel[];
  members: WorkspaceMember[];
  channelId: string;
  userId: string;
  evaluation: ChannelEffectivePermissions | null;
  loading: boolean;
  error: string | null;
  onChannelChange: (id: string) => void;
  onUserChange: (id: string) => void;
}) {
  const roleNames = useMemo(
    () => new Map(evaluation?.roles.map((role) => [role.id, role.name]) || []),
    [evaluation],
  );
  return (
    <section aria-labelledby="channel-effective-title" className="space-y-4 border-t border-discord-hover pt-6">
      <div>
        <h3 id="channel-effective-title" className="font-semibold text-white">メンバーごとの実際の権限</h3>
        <p className="mt-1 text-sm text-discord-muted">ロール、カテゴリー、チャンネル、非公開メンバーの設定を反映した権限です。</p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-sm text-discord-text">チャンネル
          <select value={channelId} onChange={(event) => onChannelChange(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
            {channels.map((channel) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
          </select>
        </label>
        <label className="text-sm text-discord-text">メンバー
          <select value={userId} onChange={(event) => onUserChange(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
            {members.map((member) => <option key={member.userId} value={member.userId}>{member.user.displayName}</option>)}
          </select>
        </label>
      </div>
      {loading && <p role="status" className="text-sm text-discord-muted">権限を計算中…</p>}
      {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
      {evaluation && !loading && (
        <div className="space-y-3">
          <p className={`rounded p-3 text-sm ${evaluation.visible ? 'bg-green-500/10 text-green-300' : 'bg-discord-red/10 text-discord-red'}`}>
            {evaluation.visible ? '閲覧可能' : '閲覧不可'}
            {evaluation.privateMembershipRequired && !evaluation.privateMember ? '（非公開メンバーではありません）' : ''}
            {evaluation.ownerProtected ? '（所有者）' : ''}
          </p>
          <ul className="grid gap-2 md:grid-cols-2">
            {evaluation.permissionDetails.map((detail) => (
              <li key={detail.permission} className={`rounded border p-3 text-xs ${detail.allowed ? 'border-green-500/30 bg-green-500/5' : 'border-discord-hover bg-discord-bg/30'}`}>
                <p className={detail.allowed ? 'font-medium text-green-300' : 'text-discord-muted'}>{detail.allowed ? '✓' : '—'} {permissionLabel(detail.permission)}</p>
                <ul className="mt-1 space-y-0.5 text-discord-muted">
                  {detail.reasons.length > 0
                    ? detail.reasons.map((reason, index) => <li key={`${detail.permission}-${index}`}>{formatChannelPermissionReason(reason, roleNames)}</li>)
                    : <li>明示的な理由はありません。</li>}
                </ul>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function PreviewMetric({ label, value, danger = false }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="rounded bg-discord-sidebar p-3">
      <dt className="text-xs text-discord-muted">{label}</dt>
      <dd className={`mt-1 font-semibold ${danger ? 'text-discord-red' : 'text-white'}`}>{value}</dd>
    </div>
  );
}

function memberNames(userIds: string[], members: WorkspaceMember[]): string {
  if (userIds.length === 0) return 'なし';
  return userIds.map((userId) => (
    members.find((member) => member.userId === userId)?.user.displayName || '不明なメンバー'
  )).join('、');
}

function bitCount(mask: number): number {
  let value = mask >>> 0;
  let count = 0;
  while (value > 0) {
    value &= value - 1;
    count += 1;
  }
  return count;
}
