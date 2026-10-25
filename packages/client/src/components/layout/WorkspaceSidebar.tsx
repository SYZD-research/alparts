import { useState } from 'react';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { Dialog } from '../ui/Dialog';
import { LanguageSelect } from '../settings/LanguageSelect';
import { useUserStateStore } from '../../stores/user-state.store';
import { summarizeWorkspaceUnread } from '../../stores/workspace-unread-model';
import { useT } from '../../i18n';
import { Icon } from '../ui/Icon';

const RAIL_TOOL = 'flex h-10 w-10 items-center justify-center rounded-xl text-muted transition-colors hover:bg-hover hover:text-ink-strong';

export function WorkspaceSidebar() {
  const t = useT();
  const { workspaces, activeWorkspaceId, setActiveWorkspace, createWorkspace } = useWorkspaceStore();
  const { logout } = useAuthStore();
  const openDmComposer = useUiStore((state) => state.openDmComposer);
  const openAccountSecurity = useUiStore((state) => state.openAccountSecurity);
  const openProfileSettings = useUiStore((state) => state.openProfileSettings);
  const openSavedMessages = useUiStore((state) => state.openSavedMessages);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isLanguageOpen, setIsLanguageOpen] = useState(false);
  const [workspaceName, setWorkspaceName] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const channelStatesByWorkspace = useUserStateStore((state) => state.channelStatesByWorkspace);
  const channelStateErrors = useUserStateStore((state) => state.errorsByWorkspace);
  const channelStateLoading = useUserStateStore((state) => state.loadingByWorkspace);

  const handleOpenDm = async () => {
    const workspaceId = activeWorkspaceId || workspaces[0]?.id;
    if (!workspaceId) return;
    if (activeWorkspaceId !== workspaceId) await setActiveWorkspace(workspaceId);
    openDmComposer(workspaceId);
  };

  const handleCreateWorkspace = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!workspaceName.trim() || isCreating) return;
    setIsCreating(true);
    setCreateError(null);
    try {
      await createWorkspace(workspaceName.trim());
      setWorkspaceName('');
      setIsCreateOpen(false);
    } catch {
      setCreateError(t('ワークスペースを作成できませんでした。もう一度お試しください'));
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="flex w-16 flex-col items-center gap-2 overflow-y-auto border-r border-line bg-panel py-3">
      <p id="workspace-unread-semantics" className="sr-only">
        {t('ワークスペースごとの未読数です。')}
      </p>
      <Dialog open={isLanguageOpen} onClose={() => setIsLanguageOpen(false)} title={t('表示言語')} size="sm">
        <LanguageSelect />
      </Dialog>
      <Dialog open={isCreateOpen} onClose={() => { if (!isCreating) setIsCreateOpen(false); }} title={t('ワークスペースを作成')} size="sm">
        <form onSubmit={handleCreateWorkspace} className="space-y-4">
          {createError && <div role="alert" className="rounded-lg bg-danger/15 px-3 py-2 text-sm text-danger">{createError}</div>}
          <label className="block text-sm text-ink">
            {t('名前')}
            <input autoFocus required maxLength={100} value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} className="mt-1 w-full rounded-lg bg-field px-3 py-2" />
          </label>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setIsCreateOpen(false)} className="rounded-lg px-3 py-2 text-sm text-muted hover:bg-hover">{t('キャンセル')}</button>
            <button type="submit" disabled={isCreating || !workspaceName.trim()} className="rounded-lg bg-accent px-4 py-2 text-sm text-on-accent disabled:opacity-40">{isCreating ? t('作成中…') : t('作成')}</button>
          </div>
        </form>
      </Dialog>
      {/* Home / DM button */}
      <button
        type="button"
        onClick={() => { void handleOpenDm(); }}
        className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-raised text-ink-soft transition-colors hover:bg-selected hover:text-ink-strong"
        title={t('DMを開始')}
        aria-label={t('DMを開始')}
      >
        <Icon name="messagePlus" size={20} />
      </button>

      <div className="h-px w-6 shrink-0 bg-line" aria-hidden="true" />

      {/* Workspace list */}
      {workspaces.map((ws) => {
        const loaded = Object.prototype.hasOwnProperty.call(channelStatesByWorkspace, ws.id);
        const summary = summarizeWorkspaceUnread(
          channelStatesByWorkspace[ws.id],
          loaded,
          channelStateErrors[ws.id],
        );
        const unreadDescription = summary.status === 'error'
          ? t('未読状態を取得できませんでした')
          : summary.status === 'loading' || (channelStateLoading[ws.id] && !loaded)
            ? t('未読状態を読み込み中')
            : t('未読{count}件', { count: summary.total });
        return (
          <div key={ws.id} className="relative shrink-0">
            <button
              type="button"
              onClick={() => { void setActiveWorkspace(ws.id); }}
              aria-describedby="workspace-unread-semantics"
              aria-label={`${ws.name}${t('、')}${unreadDescription}`}
              className={`flex h-11 w-11 items-center justify-center rounded-xl text-[13px] font-semibold transition-colors ${
                activeWorkspaceId === ws.id
                  ? 'bg-accent text-on-accent shadow-md shadow-black/30'
                  : 'bg-raised text-ink-soft hover:bg-selected hover:text-ink-strong'
              }`}
              title={`${ws.name} — ${unreadDescription}`}
            >
              {ws.name.slice(0, 2).toUpperCase()}
            </button>
            {summary.status === 'ready' && summary.badge && (
              <span
                aria-hidden="true"
                className="absolute -right-1.5 -top-1.5 h-5 min-w-5 rounded-full bg-danger px-1.5 text-center text-[10px] font-bold leading-5 text-white ring-[3px] ring-panel"
              >
                {summary.badge}
              </span>
            )}
            {!loaded && !channelStateErrors[ws.id] && channelStateLoading[ws.id] && (
              <span aria-hidden="true" className="absolute -right-1 -top-1 text-[10px] text-muted">…</span>
            )}
          </div>
        );
      })}

      {/* Add workspace */}
      <button
        type="button"
        onClick={() => { setCreateError(null); setIsCreateOpen(true); }}
        className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-dashed border-line-strong text-muted transition-colors hover:border-ink-soft hover:text-ink-strong"
        title={t('ワークスペースを追加')}
      >
        <Icon name="plus" size={20} />
      </button>

      {/* Spacer */}
      <div className="flex-1" />

      <div className="flex shrink-0 flex-col items-center gap-1">
        <button
          type="button"
          onClick={() => setIsLanguageOpen(true)}
          className={RAIL_TOOL}
          title={t('表示言語')}
          aria-label={t('表示言語を変更')}
        >
          <Icon name="globe" size={20} />
        </button>
        <button
          type="button"
          onClick={openSavedMessages}
          className={RAIL_TOOL}
          title={t('保存済みメッセージ')}
          aria-label={t('保存済みメッセージを開く')}
        >
          <Icon name="bookmark" size={20} />
        </button>
        <button
          type="button"
          onClick={openProfileSettings}
          className={RAIL_TOOL}
          title={t('プロフィール')}
          aria-label={t('プロフィールを編集')}
        >
          <Icon name="user" size={20} />
        </button>
        <button
          type="button"
          onClick={openAccountSecurity}
          className={RAIL_TOOL}
          title={t('ログイン中の端末')}
          aria-label={t('ログイン中の端末を管理')}
        >
          <Icon name="shield" size={20} />
        </button>
        <button
          type="button"
          onClick={() => { void logout(); }}
          className="flex h-10 w-10 items-center justify-center rounded-xl text-muted transition-colors hover:bg-danger/15 hover:text-danger"
          title={t('ログアウト')}
        >
          <Icon name="logout" size={20} />
        </button>
      </div>
    </div>
  );
}
