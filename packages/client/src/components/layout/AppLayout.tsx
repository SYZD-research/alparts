import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
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
import { ProfileSettingsDialog } from '../profile/ProfileSettingsDialog';
import { MemberProfileDialog } from '../profile/MemberProfileDialog';
import { ChannelManagerDialog } from '../channel/ChannelManagerDialog';
import { WorkspaceManagerDialog } from '../workspace/WorkspaceManagerDialog';
import { SavedMessagesDialog } from '../bookmark/SavedMessagesDialog';
import { useUserStateStore } from '../../stores/user-state.store';
import { useMessageStore } from '../../stores/message.store';
import { api } from '../../services/api';
import { parseMessageRoute } from '../../stores/permalink-model';
import { focusMessageElement } from '../../services/message-navigation';
import { useForumStore } from '../../stores/forum.store';
import { ResizablePane } from './ResizablePane';
import { useVoiceChannelPresence } from '../../hooks/useVoiceChannelPresence';
import { AttentionNotifications } from '../notification/AttentionNotifications';
import { useHorizontalSwipe } from '../../hooks/useHorizontalSwipe';
import { useMobileLayout } from '../../hooks/useMobileLayout';
import { useT } from '../../i18n';

type PermalinkNavigationStatus = {
  kind: 'loading' | 'success' | 'error';
  message: string;
} | null;

export function AppLayout() {
  const t = useT();
  useSocketEvents();
  useVoiceChannelPresence();

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
  const [mobilePanel, setMobilePanel] = useState<'channels' | 'chat'>('channels');
  const [membersOpen, setMembersOpen] = useState(false);
  const mobile = useMobileLayout();
  const drawerRef = useRef<HTMLElement>(null);
  const chatRef = useRef<HTMLDivElement>(null);
  const showChat = () => {
    setMobilePanel('chat');
    setMembersOpen(false);
  };
  const navigationSwipe = useHorizontalSwipe({
    enabled: mobile && !membersOpen,
    direction: mobilePanel === 'chat' ? 'right' : 'left',
    onSwipe: (distance) => {
      if (distance >= 64) {
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
        setMobilePanel('channels');
      } else if (distance <= -64) showChat();
    },
  });
  useEffect(() => {
    if (activeChannelId) setMobilePanel('chat');
    setMembersOpen(false);
  }, [activeChannelId]);
  useEffect(() => {
    // Keep both panes mounted so drafts and scroll positions survive navigation.
    if (drawerRef.current) drawerRef.current.inert = mobile && mobilePanel !== 'channels';
    if (chatRef.current) chatRef.current.inert = mobile && (mobilePanel !== 'chat' || membersOpen);
  }, [mobile, mobilePanel, membersOpen]);
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (document.querySelector('[role="dialog"]')) return;
      if (event.key === 'Escape') {
        if (membersOpen) {
          setMembersOpen(false);
          document.getElementById('members-toggle')?.focus();
        } else if (mobile && activeChannelId) setMobilePanel('chat');
      }
      if (mobile && event.altKey && (event.key === 'ArrowRight' || event.key === 'ArrowLeft')) {
        event.preventDefault();
        setMembersOpen(false);
        setMobilePanel(event.key === 'ArrowRight' ? 'channels' : 'chat');
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeChannelId, membersOpen, mobile]);
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
      setPermalinkStatus({ kind: 'error', message: t('このメッセージへのリンクを開けませんでした。') });
      return;
    }

    setPermalinkStatus({ kind: 'loading', message: t('メッセージを開いています…') });
    void (async () => {
      try {
        const authoritativeChannel = await api.getChannel(messageRoute.channelId);
        if (
          request !== permalinkRequest.current
          || authoritativeChannel.id !== messageRoute.channelId
          || authoritativeChannel.workspaceId !== messageRoute.workspaceId
        ) {
          if (request === permalinkRequest.current) throw new Error(t('リンクの内容が一致しません'));
          return;
        }

        await loadWorkspaces();
        if (request !== permalinkRequest.current) return;
        const workspaceState = useWorkspaceStore.getState();
        if (!workspaceState.workspaces.some((workspace) => workspace.id === messageRoute.workspaceId)) {
          throw new Error(t('このワークスペースを閲覧する権限がないか、存在しません'));
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
        if (!loadedChannel || loadedChannel.type === 'voice' || loadedChannel.workspaceId !== authoritativeChannel.workspaceId) {
          throw new Error(t('リンク先チャンネルを開けませんでした'));
        }
        setActiveChannel(messageRoute.channelId);
        const found = await loadMessageThroughHistory(messageRoute.channelId, messageRoute.messageId, 20);
        if (request !== permalinkRequest.current) return;
        if (!found) {
          throw new Error(t('リンク先メッセージを見つけられませんでした'));
        }
        await useForumStore.getState().revealMessage(messageRoute.channelId, messageRoute.messageId);
        if (request !== permalinkRequest.current) return;
        if (!await focusMessageElement(messageRoute.messageId)) {
          throw new Error(t('メッセージは読み込みましたが表示要素を準備できませんでした'));
        }
        if (request === permalinkRequest.current) {
          setPermalinkStatus({ kind: 'success', message: t('リンク先メッセージを表示しました。') });
        }
      } catch {
        if (request === permalinkRequest.current) {
          setPermalinkStatus({
            kind: 'error',
            message: t('このメッセージを表示できません。削除されたか、閲覧できない可能性があります。'),
          });
        }
      }
    })();
  }, [loadChannels, loadMessageThroughHistory, loadWorkspaces, messageRoute, setActiveChannel, setActiveWorkspace]);

  return (
    <div
      className={`app-layout mobile-panel-${mobilePanel} ${navigationSwipe.isDragging ? 'navigation-dragging' : ''} flex h-screen overflow-hidden`}
      style={{ '--navigation-offset': `${navigationSwipe.offsetX}px` } as CSSProperties}
    >
      {permalinkStatus && (
        <div
          role={permalinkStatus.kind === 'error' ? 'alert' : 'status'}
          className={`fixed left-1/2 top-14 z-40 flex max-w-xl -translate-x-1/2 items-center gap-3 rounded border px-4 py-2 text-sm shadow-xl ${permalinkStatus.kind === 'error' ? 'border-discord-red bg-discord-sidebar text-discord-red' : 'border-discord-hover bg-discord-sidebar text-discord-text'}`}
        >
          <span>{permalinkStatus.message}</span>
          {permalinkStatus.kind === 'error' ? (
            <button type="button" onClick={() => { setPermalinkStatus(null); navigate('/', { replace: true }); }} className="shrink-0 underline">{t('閉じる')}</button>
          ) : permalinkStatus.kind === 'success' ? (
            <button type="button" onClick={() => setPermalinkStatus(null)} className="shrink-0 underline">{t('閉じる')}</button>
          ) : null}
        </div>
      )}
      <MessageSearch
        membersOpen={membersOpen}
        membersAvailable={Boolean(activeChannelId)}
        onToggleMembers={() => setMembersOpen((open) => !open)}
        showToolbar={!mobile || mobilePanel === 'chat'}
        onNavigateToChat={showChat}
      />
      <AttentionNotifications />
      <DmComposerDialog />
      <AccountSecurityDialog />
      <ChannelManagerDialog />
      <WorkspaceManagerDialog />
      <SavedMessagesDialog />
      <ProfileSettingsDialog />
      <MemberProfileDialog />
      <aside ref={drawerRef} className="channel-drawer flex shrink-0" aria-label={t('ワークスペースとチャンネル')} aria-hidden={mobile && mobilePanel !== 'channels'} {...navigationSwipe.handlers}>
        <div className="workspace-navigation flex"><WorkspaceSidebar /></div>
        {activeWorkspaceId && (
          <div className="channel-navigation flex">
            <ResizablePane
              storageKey="alparts:channel-sidebar-width"
              defaultWidth={240}
              minWidth={176}
              maxWidth={420}
              resizeEdge="right"
              label={t('チャンネル一覧の幅を変更')}
            >
              <ChannelSidebar onNavigateToChat={showChat} />
            </ResizablePane>
          </div>
        )}
      </aside>
      <div className="conversation-layout relative flex flex-1 min-w-0 min-h-0" {...navigationSwipe.handlers}>
        <div ref={chatRef} className="chat-content flex flex-1 min-w-0 min-h-0" aria-hidden={mobile && (mobilePanel !== 'chat' || membersOpen)}>
          {activeChannelId ? (
            <ChatArea visible={!mobile || (mobilePanel === 'chat' && !membersOpen)} />
          ) : (
            <div className="flex-1 flex items-center justify-center bg-discord-bg">
              <div className="text-center text-discord-muted">
                <h2 className="text-2xl font-bold mb-2">alparts</h2>
                <p>{t('チャンネルを選択してください')}</p>
              </div>
            </div>
          )}
        </div>
        {mobile && mobilePanel === 'channels' && (
          <button type="button" className="channel-drawer-backdrop absolute inset-0 z-20 bg-black/40" onClick={showChat} aria-label={t('チャットに戻る')} />
        )}
      </div>
      {activeChannelId && membersOpen && (
        <>
          {mobile && <button type="button" className="fixed inset-x-0 bottom-0 top-12 z-30 bg-black/40" aria-label={t('メンバー一覧を閉じる')} onClick={() => setMembersOpen(false)} />}
          <aside id="member-list" className="member-navigation flex shrink-0" aria-label={t('メンバー一覧')}>
            <ResizablePane
              storageKey="alparts:member-sidebar-width"
              defaultWidth={240}
              minWidth={176}
              maxWidth={420}
              resizeEdge="left"
              label={t('メンバー一覧の幅を変更')}
            >
              <div className="flex h-full min-h-0 flex-col bg-discord-sidebar">
                <div className="flex h-11 shrink-0 items-center justify-between border-b border-discord-hover px-4">
                  <h2 className="text-sm font-bold text-white">{t('メンバー')}</h2>
                  <button type="button" className="h-10 w-10 rounded text-xl text-discord-muted hover:bg-discord-hover hover:text-white" aria-label={t('メンバー一覧を閉じる')} onClick={() => setMembersOpen(false)}>×</button>
                </div>
                <div className="min-h-0 flex-1"><UserList /></div>
              </div>
            </ResizablePane>
          </aside>
        </>
      )}
    </div>
  );
}
