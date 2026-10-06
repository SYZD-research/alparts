import { useState } from 'react';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { Dialog } from '../ui/Dialog';
import { LanguageSelect } from '../settings/LanguageSelect';
import { useUserStateStore } from '../../stores/user-state.store';
import { summarizeWorkspaceUnread } from '../../stores/workspace-unread-model';
import { useT } from '../../i18n';

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
    <div className="w-[72px] bg-discord-sidebar flex flex-col items-center py-3 gap-2 overflow-y-auto">
      <p id="workspace-unread-semantics" className="sr-only">
        {t('ワークスペースごとの未読数です。')}
      </p>
      <Dialog open={isLanguageOpen} onClose={() => setIsLanguageOpen(false)} title={t('表示言語')} size="sm">
        <LanguageSelect />
      </Dialog>
      <Dialog open={isCreateOpen} onClose={() => { if (!isCreating) setIsCreateOpen(false); }} title={t('ワークスペースを作成')} size="sm">
        <form onSubmit={handleCreateWorkspace} className="space-y-4">
          {createError && <div role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{createError}</div>}
          <label className="block text-sm text-discord-text">
            {t('名前')}
            <input autoFocus required maxLength={100} value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2" />
          </label>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setIsCreateOpen(false)} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">{t('キャンセル')}</button>
            <button type="submit" disabled={isCreating || !workspaceName.trim()} className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-40">{isCreating ? t('作成中…') : t('作成')}</button>
          </div>
        </form>
      </Dialog>
      {/* Home / DM button */}
      <button
        onClick={() => { void handleOpenDm(); }}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('DMを開始')}
        aria-label={t('DMを開始')}
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
      </button>

      <div className="w-8 h-0.5 bg-discord-bg rounded-full mx-auto" />

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
          <div key={ws.id} className="relative">
            <button
              type="button"
              onClick={() => { void setActiveWorkspace(ws.id); }}
              aria-describedby="workspace-unread-semantics"
              aria-label={`${ws.name}${t('、')}${unreadDescription}`}
              className={`w-12 h-12 rounded-2xl hover:rounded-xl flex items-center justify-center transition-all duration-200 font-bold text-lg ${
                activeWorkspaceId === ws.id
                  ? 'bg-discord-accent text-white rounded-xl'
                  : 'bg-discord-bg hover:bg-discord-accent text-discord-muted hover:text-white'
              }`}
              title={`${ws.name} — ${unreadDescription}`}
            >
              {ws.name.slice(0, 2).toUpperCase()}
            </button>
            {summary.status === 'ready' && summary.badge && (
              <span
                aria-hidden="true"
                className="absolute -right-2 -top-1 min-w-5 rounded-full bg-discord-red px-1 text-center text-[10px] font-bold text-white"
              >
                {summary.badge}
              </span>
            )}
            {!loaded && !channelStateErrors[ws.id] && channelStateLoading[ws.id] && (
              <span aria-hidden="true" className="absolute -right-1 -top-1 text-[10px] text-discord-muted">…</span>
            )}
          </div>
        );
      })}

      {/* Add workspace */}
      <button
        onClick={() => { setCreateError(null); setIsCreateOpen(true); }}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-green hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-green hover:text-white"
        title={t('ワークスペースを追加')}
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
          <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
        </svg>
      </button>

      {/* Spacer */}
      <div className="flex-1" />

      <button
        type="button"
        onClick={() => setIsLanguageOpen(true)}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('表示言語')}
        aria-label={t('表示言語を変更')}
      >
        <span aria-hidden="true">🌐</span>
      </button>
      <button
        type="button"
        onClick={openSavedMessages}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('保存済みメッセージ')}
        aria-label={t('保存済みメッセージを開く')}
      >
        <span aria-hidden="true">🔖</span>
      </button>
      <button
        type="button"
        onClick={openProfileSettings}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('プロフィール')}
        aria-label={t('プロフィールを編集')}
      >
        <span aria-hidden="true">👤</span>
      </button>
      <button
        onClick={openAccountSecurity}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('ログイン中の端末')}
        aria-label={t('ログイン中の端末を管理')}
      >
        <span aria-hidden="true">🛡</span>
      </button>
      <button
        onClick={() => { void logout(); }}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-red hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title={t('ログアウト')}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
          <path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>
        </svg>
      </button>
    </div>
  );
}
