import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiError, api, type WorkspaceInvitation, type WorkspaceRole } from '../../services/api';
import {
  invitationStatusAt,
  managementErrorMessage,
} from '../../stores/workspace-management-model';

interface InvitationManagerProps {
  mode: 'accept' | 'manage';
  workspaceId: string;
  roles: WorkspaceRole[];
  canChooseRole: boolean;
  onAccepted: (workspaceId: string) => Promise<void>;
}

const statusLabels: Record<WorkspaceInvitation['status'], string> = {
  active: '有効',
  used: '使用済み',
  revoked: '無効',
  expired: '期限切れ',
};

const expirationOptions = [
  { value: 60 * 60, label: '1時間' },
  { value: 24 * 60 * 60, label: '1日' },
  { value: 7 * 24 * 60 * 60, label: '7日' },
  { value: 30 * 24 * 60 * 60, label: '30日' },
];

export function InvitationManager({
  mode,
  workspaceId,
  roles,
  canChooseRole,
  onAccepted,
}: InvitationManagerProps) {
  const [token, setToken] = useState('');
  const [accepting, setAccepting] = useState(false);
  const [acceptError, setAcceptError] = useState<string | null>(null);
  const [acceptResult, setAcceptResult] = useState<string | null>(null);
  const [invitations, setInvitations] = useState<WorkspaceInvitation[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [roleId, setRoleId] = useState('');
  const [expiresInSeconds, setExpiresInSeconds] = useState(7 * 24 * 60 * 60);
  const [saving, setSaving] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [pendingRevokeId, setPendingRevokeId] = useState<string | null>(null);
  const tokenInputRef = useRef<HTMLInputElement>(null);
  const loadGeneration = useRef(0);

  const availableRoles = roles.filter((role) => role.name.toLowerCase() !== 'owner');

  const loadInvitations = async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setLoadError(null);
    try {
      const next = await api.getInvitations(workspaceId);
      if (generation === loadGeneration.current) setInvitations(next);
    } catch (error) {
      if (generation === loadGeneration.current) {
        setInvitations([]);
        setLoadError(managementErrorMessage(error, '招待一覧を読み込めませんでした'));
      }
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  };

  useEffect(() => {
    setCreatedToken(null);
    setCopied(false);
    setPendingRevokeId(null);
    if (mode === 'manage') void loadInvitations();
    return () => { loadGeneration.current += 1; };
    // loadInvitations intentionally starts a workspace-scoped request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, workspaceId]);

  useEffect(() => {
    if (!canChooseRole || roleId && availableRoles.some((role) => role.id === roleId)) return;
    setRoleId(availableRoles.find((role) => role.name === 'Member')?.id || availableRoles[0]?.id || '');
  }, [availableRoles, canChooseRole, roleId]);

  const submitAccept = async (event: FormEvent) => {
    event.preventDefault();
    const submittedToken = token.trim();
    if (submittedToken.length < 32) {
      setAcceptError('有効な招待コードを入力してください。');
      return;
    }
    setAccepting(true);
    setAcceptError(null);
    setAcceptResult(null);
    try {
      const accepted = await api.acceptInvitation(submittedToken);
      setToken('');
      await onAccepted(accepted.workspaceId);
      setAcceptResult('招待を受諾し、対象ワークスペースへ移動しました。');
    } catch (error) {
      setAcceptError(error instanceof ApiError && error.status === 403
        ? '招待コードが無効、使用済み、期限切れ、またはメールアドレスが一致していません。'
        : managementErrorMessage(error, '招待を受諾できませんでした'));
    } finally {
      setAccepting(false);
    }
  };

  if (mode === 'accept') {
    return (
      <form onSubmit={submitAccept} className="space-y-4">
        <div>
          <h3 className="font-semibold text-white">既存アカウントで招待を受諾</h3>
          <p className="mt-1 text-sm text-discord-muted">受け取った招待コードを入力してください。</p>
        </div>
        <label className="block text-sm text-discord-text">
          招待コード
          <input
            autoFocus
            type="text"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="mt-1 w-full rounded bg-discord-bg px-3 py-2 font-mono text-sm text-white"
            aria-describedby="invitation-token-help"
          />
        </label>
        <p id="invitation-token-help" className="text-xs text-discord-muted">メールアドレスが指定された招待は、そのアカウントだけが利用できます。</p>
        {acceptError && <p role="alert" className="text-sm text-discord-red">{acceptError}</p>}
        {acceptResult && <p role="status" className="text-sm text-green-400">{acceptResult}</p>}
        <button type="submit" disabled={accepting} className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
          {accepting ? '受諾中…' : '招待を受諾'}
        </button>
      </form>
    );
  }

  const submitCreate = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setMutationError(null);
    setCreatedToken(null);
    setCopied(false);
    try {
      const created = await api.createInvitation(workspaceId, {
        ...(email.trim() ? { email: email.trim() } : {}),
        ...(canChooseRole && roleId ? { roleId } : {}),
        expiresInSeconds,
      });
      // Keep the secret only in this ephemeral component state. It is never added to the list/store.
      setCreatedToken(created.token);
      setEmail('');
      await loadInvitations();
    } catch (error) {
      setMutationError(managementErrorMessage(error, '招待を作成できませんでした'));
    } finally {
      setSaving(false);
    }
  };

  const copyCreatedToken = async () => {
    if (!createdToken) return;
    try {
      await navigator.clipboard.writeText(createdToken);
      setCopied(true);
    } catch {
      tokenInputRef.current?.focus();
      tokenInputRef.current?.select();
      setMutationError('自動コピーできませんでした。選択済みのコードを手動でコピーしてください。');
    }
  };

  const revoke = async (invitationId: string) => {
    setSaving(true);
    setMutationError(null);
    try {
      await api.revokeInvitation(workspaceId, invitationId);
      setPendingRevokeId(null);
      await loadInvitations();
    } catch (error) {
      setMutationError(managementErrorMessage(error, '招待を無効にできませんでした'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <form onSubmit={submitCreate} className="space-y-4 rounded bg-discord-bg/40 p-4">
        <div>
          <h3 className="font-semibold text-white">招待を作成</h3>
          <p className="mt-1 text-xs text-discord-muted">メールアドレスを空欄にすると、コードを受け取った人が利用できます。</p>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          <label className="text-sm text-discord-text">
            メールアドレス（任意）
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white" maxLength={254} />
          </label>
          {canChooseRole ? (
            <label className="text-sm text-discord-text">
              付与ロール
              <select value={roleId} onChange={(event) => setRoleId(event.target.value)} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white" required>
                {availableRoles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}
              </select>
            </label>
          ) : (
            <div className="text-sm text-discord-text">
              付与ロール
              <div className="mt-1 rounded bg-discord-bg px-3 py-2 text-discord-muted">Member（既定）</div>
            </div>
          )}
          <label className="text-sm text-discord-text">
            有効期限
            <select value={expiresInSeconds} onChange={(event) => setExpiresInSeconds(Number(event.target.value))} className="mt-1 w-full rounded bg-discord-bg px-3 py-2 text-white">
              {expirationOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
        </div>
        <button type="submit" disabled={saving || canChooseRole && !roleId} className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
          {saving ? '作成中…' : '招待を作成'}
        </button>
      </form>

      {createdToken && (
        <section role="status" className="rounded border border-yellow-500/60 bg-yellow-500/10 p-4">
          <h3 className="font-semibold text-yellow-200">今すぐコードを保存してください</h3>
          <p className="mt-1 text-sm text-yellow-100">このコードは作成直後のこの画面でだけ表示されます。閉じた後や一覧からの再表示はできません。</p>
          <div className="mt-3 flex gap-2">
            <input ref={tokenInputRef} readOnly value={createdToken} onFocus={(event) => event.currentTarget.select()} aria-label="作成された招待コード" className="min-w-0 flex-1 rounded bg-discord-bg px-3 py-2 font-mono text-sm text-white" />
            <button type="button" onClick={() => void copyCreatedToken()} className="rounded bg-discord-accent px-3 py-2 text-sm text-white">{copied ? 'コピー済み' : 'コピー'}</button>
          </div>
          <button type="button" onClick={() => { setCreatedToken(null); setCopied(false); }} className="mt-3 text-sm text-discord-muted underline hover:text-white">保存済みとして非表示</button>
        </section>
      )}

      {mutationError && <p role="alert" className="text-sm text-discord-red">{mutationError}</p>}

      <section aria-labelledby="invitation-list-title">
        <div className="flex items-center justify-between gap-3">
          <h3 id="invitation-list-title" className="font-semibold text-white">招待一覧</h3>
          <button type="button" onClick={() => void loadInvitations()} disabled={loading} className="rounded px-3 py-1 text-sm text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">再読み込み</button>
        </div>
        {loading && <p role="status" className="mt-3 text-sm text-discord-muted">読み込み中…</p>}
        {loadError && <p role="alert" className="mt-3 text-sm text-discord-red">{loadError}</p>}
        {!loading && !loadError && invitations.length === 0 && <p className="mt-3 text-sm text-discord-muted">招待はありません。</p>}
        <ul className="mt-3 space-y-2">
          {invitations.map((invitation) => {
            const status = invitationStatusAt(invitation, Date.now());
            return (
              <li key={invitation.id} className="rounded bg-discord-bg/50 p-3 text-sm">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-medium text-white">{invitation.email || 'メールアドレス指定なし'} · {invitation.role?.name || '削除済みロール'}</p>
                    <p className="mt-1 text-xs text-discord-muted">状態: {statusLabels[status]} / 期限: {new Date(invitation.expiresAt).toLocaleString()}</p>
                  </div>
                  {status === 'active' && pendingRevokeId !== invitation.id && (
                    <button type="button" onClick={() => setPendingRevokeId(invitation.id)} className="rounded px-3 py-1 text-discord-red hover:bg-discord-red/10">無効にする</button>
                  )}
                </div>
                {pendingRevokeId === invitation.id && (
                  <div role="group" aria-label="招待を無効にする確認" className="mt-3 flex flex-wrap items-center gap-2 rounded border border-discord-red/40 p-2">
                    <span className="text-discord-text">このコードを即時無効にしますか？</span>
                    <button autoFocus type="button" onClick={() => void revoke(invitation.id)} disabled={saving} className="rounded bg-discord-red px-3 py-1 text-white disabled:opacity-50">無効にする</button>
                    <button type="button" onClick={() => setPendingRevokeId(null)} className="rounded px-3 py-1 text-discord-muted hover:bg-discord-hover hover:text-white">キャンセル</button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}
