import { useEffect } from 'react';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useChannelStore } from '../../stores/channel.store';
import { useSocketEvents } from '../../hooks/useSocketEvents';
import { WorkspaceSidebar } from './WorkspaceSidebar';
import { ChannelSidebar } from './ChannelSidebar';
import { ChatArea } from './ChatArea';
import { UserList } from '../user/UserList';

export function AppLayout() {
  useSocketEvents();

  const { loadWorkspaces, activeWorkspaceId } = useWorkspaceStore();
  const { activeChannelId } = useChannelStore();

  useEffect(() => {
    loadWorkspaces();
  }, []);

  return (
    <div className="flex h-screen overflow-hidden">
      <WorkspaceSidebar />
      {activeWorkspaceId && <ChannelSidebar />}
      <div className="flex flex-1 min-w-0">
        {activeChannelId ? (
          <>
            <ChatArea />
            <UserList />
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center bg-discord-bg">
            <div className="text-center text-discord-muted">
              <h2 className="text-2xl font-bold mb-2">alparts</h2>
              <p>チャンネルを選択してください</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
