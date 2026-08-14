import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';

export function WorkspaceSidebar() {
  const { workspaces, activeWorkspaceId, setActiveWorkspace, createWorkspace } = useWorkspaceStore();
  const { logout } = useAuthStore();

  const handleCreateWorkspace = () => {
    const name = prompt('ワークスペース名を入力してください:');
    if (name?.trim()) {
      createWorkspace(name.trim());
    }
  };

  return (
    <div className="w-[72px] bg-discord-sidebar flex flex-col items-center py-3 gap-2 overflow-y-auto">
      {/* Home / DM button */}
      <button
        onClick={() => {}}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-accent hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title="DM"
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
      </button>

      <div className="w-8 h-0.5 bg-discord-bg rounded-full mx-auto" />

      {/* Workspace list */}
      {workspaces.map((ws) => (
        <button
          key={ws.id}
          onClick={() => setActiveWorkspace(ws.id)}
          className={`w-12 h-12 rounded-2xl hover:rounded-xl flex items-center justify-center transition-all duration-200 font-bold text-lg ${
            activeWorkspaceId === ws.id
              ? 'bg-discord-accent text-white rounded-xl'
              : 'bg-discord-bg hover:bg-discord-accent text-discord-muted hover:text-white'
          }`}
          title={ws.name}
        >
          {ws.name.slice(0, 2).toUpperCase()}
        </button>
      ))}

      {/* Add workspace */}
      <button
        onClick={handleCreateWorkspace}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-green hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-green hover:text-white"
        title="ワークスペースを追加"
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
          <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
        </svg>
      </button>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Logout */}
      <button
        onClick={logout}
        className="w-12 h-12 rounded-2xl bg-discord-bg hover:bg-discord-red hover:rounded-xl flex items-center justify-center transition-all duration-200 text-discord-muted hover:text-white"
        title="ログアウト"
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
          <path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>
        </svg>
      </button>
    </div>
  );
}
