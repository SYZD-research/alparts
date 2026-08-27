import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useChannelStore } from '../../stores/channel.store';
import { useAuthStore } from '../../stores/auth.store';
import { useOutboxStore } from '../../stores/outbox.store';
import { useSocketEvents } from '../../hooks/useSocketEvents';
import { WorkspaceSidebar } from './WorkspaceSidebar';
import { ChannelSidebar } from './ChannelSidebar';
import { ChatArea } from './ChatArea';
import { UserList } from '../user/UserList';
import { MessageSearch } from '../search/MessageSearch';
import { DmComposerDialog } from '../dm/DmComposerDialog';
import { useDmStore } from '../../stores/dm.store';
import { AccountSecurityDialog } from '../security/AccountSecurityDialog';
import { ChannelManagerDialog } from '../channel/ChannelManagerDialog';
import { WorkspaceManagerDialog } from '../workspace/WorkspaceManagerDialog';
import { SavedMessagesDialog } from '../bookmark/SavedMessagesDialog';
import { useUserStateStore } from '../../stores/user-state.store';
import { useMessageStore } from '../../stores/message.store';
import { api } from '../../services/api';
import { parseMessageRoute } from '../../stores/permalink-model';

type PermalinkNavigationStatus = {
  kind: 'loading' | 'success' | 'error';
  message: string;
} | null;

export function AppLayout() {
  useSocketEvents();

  const location = useLocation();
  const navigate = useNavigate();
  const { loadWorkspaces, activeWorkspaceId, workspaces, setActiveWorkspace } = useWorkspaceStore();
  const { activeChannelId, setActiveChannel, loadChannels } = useChannelStore();
  const userId = useAuthStore((state) => state.user?.id);
  const initializeOutbox = useOutboxStore((state) => state.initialize);
  const flushOutbox = useOutboxStore((state) => state.flushAll);
  const loadDms = useDmStore((state) => state.loadDms);
  const loadAllWorkspaceStates = useUserStateStore((state) => state.loadAllWorkspaceStates);
  const loadBookmarks = useUserStateStore((state) => state.loadBookmarks);
  const loadMessageThroughHistory = useMessageStore((state) => state.loadMessageThroughHistory);
  const [permalinkStatus, setPermalinkStatus] = useState<PermalinkNavigationStatus>(null);
  const permalinkRequest = useRef(0);
  const messageRoute = useMemo(() => parseMessageRoute(location.pathname), [location.pathname]);
  const workspaceIds = useMemo(() => workspaces.map((workspace) => workspace.id), [workspaces]);

  useEffect(() => {
    void loadWorkspaces();
  }, [loadWorkspaces]);

  useEffect(() => {
    if (!userId) return;
    void initializeOutbox().then(() => {
      if (navigator.onLine) void flushOutbox();
    }).catch(() => undefined);
    const onOnline = () => { void flushOutbox(); };
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  }, [flushOutbox, initializeOutbox, userId]);

  useEffect(() => {
    if (!activeWorkspaceId) return;
    void loadDms(activeWorkspaceId);
  }, [activeWorkspaceId, loadDms]);

  useEffect(() => {
    if (!userId || workspaceIds.length === 0) return;
    void loadAllWorkspaceStates(workspaceIds, 4);
  }, [loadAllWorkspaceStates, userId, workspaceIds]);

  useEffect(() => {
    if (workspaceIds.length === 0 && !activeWorkspaceId) return;
    const refreshWhenVisible = () => {
      if (document.visibilityState !== 'visible') return;
      const ids = workspaceIds.length > 0 ? workspaceIds : activeWorkspaceId ? [activeWorkspaceId] : [];
      void loadAllWorkspaceStates(ids, 4);
    };
    const refreshWhenOnline = () => refreshWhenVisible();
    window.addEventListener('focus', refreshWhenVisible);
    window.addEventListener('online', refreshWhenOnline);
    document.addEventListener('visibilitychange', refreshWhenVisible);
    return () => {
      window.removeEventListener('focus', refreshWhenVisible);
      window.removeEventListener('online', refreshWhenOnline);
      document.removeEventListener('visibilitychange', refreshWhenVisible);
    };
  }, [activeWorkspaceId, loadAllWorkspaceStates, workspaceIds]);

  useEffect(() => {
    if (userId) void loadBookmarks();
  }, [loadBookmarks, userId]);

  useEffect(() => {
    const request = ++permalinkRequest.current;
    if (messageRoute.kind === 'none') {
      setPermalinkStatus(null);
      return;
    }
    if (messageRoute.kind === 'invalid') {
      setPermalinkStatus({ kind: 'error', message: 'メッセージリンクのUUID形式が不正です。サーバーへは送信していません。' });
      return;
    }

    setPermalinkStatus({ kind: 'loading', message: 'メッセージリンクを検証し、暗号化履歴を読み込んでいます…' });
    void (async () => {
      try {
        const authoritativeChannel = await api.getChannel(messageRoute.channelId);
        if (
          request !== permalinkRequest.current
          || authoritativeChannel.id !== messageRoute.channelId
          || authoritativeChannel.workspaceId !== messageRoute.workspaceId
        ) {
          if (request === permalinkRequest.current) throw new Error('リンクのworkspaceとchannelが一致しません');
          return;
        }

        await loadWorkspaces();
        if (request !== permalinkRequest.current) return;
        const workspaceState = useWorkspaceStore.getState();
        if (!workspaceState.workspaces.some((workspace) => workspace.id === messageRoute.workspaceId)) {
          throw new Error('このワークスペースを閲覧する権限がないか、存在しません');
        }

        if (workspaceState.activeWorkspaceId !== messageRoute.workspaceId) {
          await setActiveWorkspace(messageRoute.workspaceId);
        } else {
          const channelState = useChannelStore.getState();
          if (channelState.workspaceId !== messageRoute.workspaceId || !channelState.channels.some((channel) => channel.id === messageRoute.channelId)) {
            await loadChannels(messageRoute.workspaceId);
          }
        }
        if (request !== permalinkRequest.current) return;

        const loadedChannel = useChannelStore.getState().channels.find((channel) => channel.id === messageRoute.channelId);
        if (!loadedChannel || loadedChannel.workspaceId !== authoritativeChannel.workspaceId) {
          throw new Error('検証済みチャンネルをワークスペース内で開けませんでした');
        }
        setActiveChannel(messageRoute.channelId);
        const found = await loadMessageThroughHistory(messageRoute.channelId, messageRoute.messageId, 20);
        if (request !== permalinkRequest.current) return;
        if (!found) {
          const loadError = useMessageStore.getState().securityErrors[messageRoute.channelId];
          if (loadError) throw new Error(`リンク先履歴を安全に読み込めませんでした: ${loadError}`);
          throw new Error('過去20ページ以内にリンク先メッセージを見つけられませんでした');
        }
        if (!await focusPermalinkMessage(messageRoute.messageId)) {
          throw new Error('メッセージは読み込みましたが表示要素を準備できませんでした');
        }
        if (request === permalinkRequest.current) {
          setPermalinkStatus({ kind: 'success', message: 'リンク先メッセージを表示しました。' });
        }
      } catch (error) {
        if (request === permalinkRequest.current) {
          setPermalinkStatus({
            kind: 'error',
            message: error instanceof Error ? error.message : 'メッセージリンクを開けませんでした',
          });
        }
      }
    })();
  }, [loadChannels, loadMessageThroughHistory, loadWorkspaces, messageRoute, setActiveChannel, setActiveWorkspace]);

  return (
    <div className="flex h-screen overflow-hidden">
      {permalinkStatus && (
        <div
          role={permalinkStatus.kind === 'error' ? 'alert' : 'status'}
          className={`fixed left-1/2 top-14 z-40 flex max-w-xl -translate-x-1/2 items-center gap-3 rounded border px-4 py-2 text-sm shadow-xl ${permalinkStatus.kind === 'error' ? 'border-discord-red bg-discord-sidebar text-discord-red' : 'border-discord-hover bg-discord-sidebar text-discord-text'}`}
        >
          <span>{permalinkStatus.message}</span>
          {permalinkStatus.kind === 'error' ? (
            <button type="button" onClick={() => { setPermalinkStatus(null); navigate('/', { replace: true }); }} className="shrink-0 underline">閉じる</button>
          ) : permalinkStatus.kind === 'success' ? (
            <button type="button" onClick={() => setPermalinkStatus(null)} className="shrink-0 underline">閉じる</button>
          ) : null}
        </div>
      )}
      <MessageSearch />
      <DmComposerDialog />
      <AccountSecurityDialog />
      <ChannelManagerDialog />
      <WorkspaceManagerDialog />
      <SavedMessagesDialog />
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

async function focusPermalinkMessage(messageId: string): Promise<boolean> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const target = document.getElementById(`message-${messageId}`);
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ block: 'center', behavior: 'smooth' });
      target.focus({ preventScroll: true });
      target.dataset.permalinkHighlight = 'true';
      window.setTimeout(() => {
        if (target.dataset.permalinkHighlight === 'true') delete target.dataset.permalinkHighlight;
      }, 4000);
      return true;
    }
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
  return false;
}
