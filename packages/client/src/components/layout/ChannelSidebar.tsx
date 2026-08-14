import { useState } from 'react';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useChannelStore } from '../../stores/channel.store';
import { useAuthStore } from '../../stores/auth.store';

export function ChannelSidebar() {
  const { activeWorkspaceId, categories, loadCategories } = useWorkspaceStore();
  const { channels, activeChannelId, setActiveChannel, createChannel, loadChannels } = useChannelStore();
  const { user } = useAuthStore();
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());

  const toggleCategory = (id: string) => {
    setCollapsedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleCreateChannel = () => {
    if (!activeWorkspaceId) return;
    const name = prompt('チャンネル名を入力してください:');
    if (name?.trim()) {
      createChannel(activeWorkspaceId, name.trim().toLowerCase().replace(/\s+/g, '-'));
    }
  };

  if (!activeWorkspaceId) return null;

  const textChannels = channels.filter(c => c.type === 'text');

  return (
    <div className="w-60 bg-discord-sidebar flex flex-col">
      {/* Workspace header */}
      <div className="h-12 px-4 flex items-center border-b border-discord-bg shadow-sm">
        <h2 className="font-bold text-white truncate">
          {useWorkspaceStore.getState().workspaces.find(w => w.id === activeWorkspaceId)?.name || 'ワークスペース'}
        </h2>
      </div>

      {/* Channel list */}
      <div className="flex-1 overflow-y-auto px-2 pt-4">
        {/* Categories */}
        {categories.map(category => (
          <div key={category.id} className="mb-1">
            <button
              onClick={() => toggleCategory(category.id)}
              className="flex items-center w-full px-1 py-1 text-xs font-bold text-discord-muted hover:text-discord-text uppercase tracking-wide"
            >
              <svg
                width="12" height="12" viewBox="0 0 12 12"
                className={`mr-0.5 transition-transform ${collapsedCategories.has(category.id) ? '-rotate-90' : ''}`}
                fill="currentColor"
              >
                <path d="M2 4l4 4 4-4"/>
              </svg>
              {category.name}
            </button>

            {!collapsedCategories.has(category.id) && (
              <div className="ml-2">
                {category.channels
                  .filter(ch => ch.type === 'text')
                  .map(channel => (
                    <button
                      key={channel.id}
                      onClick={() => setActiveChannel(channel.id)}
                      className={`flex items-center w-full px-2 py-1.5 rounded text-sm group transition-colors ${
                        activeChannelId === channel.id
                          ? 'bg-discord-active text-white'
                          : 'text-discord-channel hover:text-discord-text hover:bg-discord-hover'
                      }`}
                    >
                      <span className="mr-1.5 text-discord-muted">#</span>
                      <span className="truncate">{channel.name}</span>
                    </button>
                  ))}
              </div>
            )}
          </div>
        ))}

        {/* Channels without category */}
        {textChannels.filter(c => !c.categoryId).length > 0 && (
          <div className="mb-1">
            <div className="px-1 py-1 text-xs font-bold text-discord-muted uppercase tracking-wide">
              チャンネル
            </div>
            {textChannels.filter(c => !c.categoryId).map(channel => (
              <button
                key={channel.id}
                onClick={() => setActiveChannel(channel.id)}
                className={`flex items-center w-full px-2 py-1.5 rounded text-sm group transition-colors ${
                  activeChannelId === channel.id
                    ? 'bg-discord-active text-white'
                    : 'text-discord-channel hover:text-discord-text hover:bg-discord-hover'
                }`}
              >
                <span className="mr-1.5 text-discord-muted">#</span>
                <span className="truncate">{channel.name}</span>
              </button>
            ))}
          </div>
        )}

        {/* Add channel button */}
        <button
          onClick={handleCreateChannel}
          className="flex items-center w-full px-2 py-1.5 rounded text-sm text-discord-muted hover:text-discord-text hover:bg-discord-hover"
        >
          <span className="mr-1.5">+</span>
          チャンネルを追加
        </button>
      </div>

      {/* User area */}
      {user && (
        <div className="h-14 px-2 flex items-center bg-discord-bg/50">
          <div className="flex items-center gap-2 px-2 py-1 rounded hover:bg-discord-hover cursor-pointer flex-1 min-w-0">
            <div className="w-8 h-8 rounded-full bg-discord-accent flex items-center justify-center text-white text-sm font-bold">
              {user.displayName.slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-medium text-white truncate">{user.displayName}</div>
              <div className="text-xs text-discord-muted truncate">オンライン</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
