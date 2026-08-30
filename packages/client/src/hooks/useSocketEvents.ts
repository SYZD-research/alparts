import { useEffect } from 'react';
import type { Attachment, Device, Message, Reaction, ReadPosition, UserStatusType } from '@alparts/shared';
import { ensureChannelKey, getActiveDevice } from '../services/crypto.service';
import { getSocket } from '../services/socket';
import type { DirectMessageConversation } from '../services/api';
import { useAttachmentStore } from '../stores/attachment.store';
import {
  parseChannelAuthorizationEvent,
  parseWorkspaceAccessRevokedEvent,
  parseWorkspaceAuthorizationRefresh,
} from '../stores/authorization-event-model';
import { useAuthStore } from '../stores/auth.store';
import { useChannelStore } from '../stores/channel.store';
import { useDmStore } from '../stores/dm.store';
import { useMessageStore } from '../stores/message.store';
import { useOutboxStore } from '../stores/outbox.store';
import { usePresenceStore } from '../stores/presence.store';
import { clearChannelSecurityScope, clearWorkspaceSecurityScope } from '../stores/security-scope-cleanup';
import { useUserStateStore } from '../stores/user-state.store';
import { useUiStore } from '../stores/ui.store';
import { useWorkspaceStore } from '../stores/workspace.store';

export function useSocketEvents() {
  const addMessage = useMessageStore((state) => state.addMessage);
  const removeMessage = useMessageStore((state) => state.removeMessage);
  const applyReactionUpdate = useMessageStore((state) => state.applyReactionUpdate);
  const applyPinUpdate = useMessageStore((state) => state.applyPinUpdate);
  const applyAttachment = useMessageStore((state) => state.applyAttachment);
  const setStatus = usePresenceStore((state) => state.setStatus);
  const setTyping = usePresenceStore((state) => state.setTyping);
  const loadMessages = useMessageStore((state) => state.loadMessages);
  const flushOutbox = useOutboxStore((state) => state.flushAll);
  const upsertDm = useDmStore((state) => state.upsertDm);
  const loadChannels = useChannelStore((state) => state.loadChannels);
  const noteBaseMessage = useUserStateStore((state) => state.noteBaseMessage);
  const applySocketReadPosition = useUserStateStore((state) => state.applySocketReadPosition);
  const loadWorkspaceState = useUserStateStore((state) => state.loadWorkspaceState);
  const loadWorkspaces = useWorkspaceStore((state) => state.loadWorkspaces);
  const loadMembers = useWorkspaceStore((state) => state.loadMembers);
  const setActiveWorkspace = useWorkspaceStore((state) => state.setActiveWorkspace);
  const userId = useAuthStore((state) => state.user?.id);
  const resumeFailedUploads = useAttachmentStore((state) => state.resumeFailedUploads);

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    let rejoinTimer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    let authorizationQueue = Promise.resolve();
    let authorizationQueueDepth = 0;
    const pendingKeySyncIds = new Set<string>();
    let keySyncRunning = false;
    const maxPendingAuthorizationTasks = 64;

    const isAuthorizedLoadedChannel = (channelId: string) => (
      useChannelStore.getState().channels.some((channel) => channel.id === channelId)
      && (
        Object.prototype.hasOwnProperty.call(useMessageStore.getState().eventsByChannel, channelId)
        || useMessageStore.getState().loadingByChannel[channelId] === true
      )
    );

    const enqueueAuthorizationWork = (operation: () => Promise<void>) => {
      // Revocation handlers erase the affected security scope before entering
      // this queue. Dropping later reconciliation work at the exact cap is
      // therefore fail-closed and a reconnect will rebuild the visible state.
      if (authorizationQueueDepth >= maxPendingAuthorizationTasks) return;
      authorizationQueueDepth += 1;
      authorizationQueue = authorizationQueue
        .catch(() => undefined)
        .then(async () => {
          if (!disposed) await operation();
        })
        .catch(() => undefined)
        .finally(() => { authorizationQueueDepth -= 1; });
    };

    const scheduleKeySync = (channelIds: string[]) => {
      for (const channelId of channelIds) {
        if (isAuthorizedLoadedChannel(channelId)) pendingKeySyncIds.add(channelId);
      }
      if (keySyncRunning || pendingKeySyncIds.size === 0) return;
      keySyncRunning = true;
      void (async () => {
        while (!disposed && pendingKeySyncIds.size > 0) {
          const channelId = pendingKeySyncIds.values().next().value as string;
          pendingKeySyncIds.delete(channelId);
          if (!isAuthorizedLoadedChannel(channelId)) continue;
          try {
            await ensureChannelKey(channelId);
            useMessageStore.getState().retryUnavailableMessages(channelId);
          } catch {
            // Another device may complete distribution. Missing/revoked keys
            // remain fail-closed and surface through the message flow.
          }
        }
      })().finally(() => {
        keySyncRunning = false;
        pendingKeySyncIds.clear();
      });
    };

    const syncLoadedWorkspaceKeys = (workspaceId: string) => {
      const workspaceState = useWorkspaceStore.getState();
      const channelState = useChannelStore.getState();
      if (workspaceState.activeWorkspaceId !== workspaceId || channelState.workspaceId !== workspaceId) return;
      scheduleKeySync(channelState.channels.map((channel) => channel.id));
    };

    const refreshWorkspaceAuthorization = async (workspaceId: string) => {
      const workspaceState = useWorkspaceStore.getState();
      if (workspaceState.activeWorkspaceId !== workspaceId) {
        await loadWorkspaceState(workspaceId);
        if (useUserStateStore.getState().errorsByWorkspace[workspaceId]) {
          useUserStateStore.getState().clearWorkspace(workspaceId);
        }
        return;
      }

      const before = useChannelStore.getState();
      const previousChannelIds = before.workspaceId === workspaceId
        ? before.channels.map((channel) => channel.id)
        : [];
      await loadChannels(workspaceId);
      const after = useChannelStore.getState();
      if (after.workspaceId !== workspaceId || after.error) {
        await Promise.allSettled(previousChannelIds.map((channelId) => (
          clearChannelSecurityScope(workspaceId, channelId)
        )));
        useUserStateStore.getState().clearWorkspace(workspaceId);
        return;
      }

      // `loadChannels` deliberately returns its raw response even when a newer
      // generation invalidates it. Authorization decisions must use only the
      // generation-checked store projection.
      const visibleIds = new Set(after.channels.map((channel) => channel.id));
      await Promise.allSettled(previousChannelIds
        .filter((channelId) => !visibleIds.has(channelId))
        .map((channelId) => clearChannelSecurityScope(workspaceId, channelId)));
      await Promise.allSettled([loadWorkspaceState(workspaceId), loadMembers(workspaceId)]);
      syncLoadedWorkspaceKeys(workspaceId);
    };

    const selectReplacementWorkspace = async () => {
      const state = useWorkspaceStore.getState();
      if (state.activeWorkspaceId || state.workspaces.length === 0) return;
      await setActiveWorkspace(state.workspaces[0].id);
      await loadWorkspaceState(state.workspaces[0].id);
    };

    const reconcileWorkspaceMembership = async (): Promise<boolean> => {
      const beforeWorkspace = useWorkspaceStore.getState();
      const knownWorkspaceIds = new Set([
        ...beforeWorkspace.workspaces.map((workspace) => workspace.id),
        ...Object.keys(useUserStateStore.getState().channelStatesByWorkspace),
      ]);
      const previousActiveWorkspaceId = beforeWorkspace.activeWorkspaceId;
      const workspaces = await loadWorkspaces();
      if (!workspaces || disposed || useWorkspaceStore.getState().error) return false;

      const visibleWorkspaceIds = new Set(
        useWorkspaceStore.getState().workspaces.map((workspace) => workspace.id),
      );
      await Promise.allSettled([...knownWorkspaceIds]
        .filter((workspaceId) => !visibleWorkspaceIds.has(workspaceId))
        .map((workspaceId) => clearWorkspaceSecurityScope(workspaceId)));

      if (previousActiveWorkspaceId && visibleWorkspaceIds.has(previousActiveWorkspaceId)) {
        await refreshWorkspaceAuthorization(previousActiveWorkspaceId);
      } else {
        await selectReplacementWorkspace();
      }
      return !disposed;
    };

    const onMessageNew = (data: { message: Message }) => {
      if (!isAuthorizedLoadedChannel(data.message.channelId)) return;
      addMessage(data.message.channelId, data.message);
      noteBaseMessage(data.message);
    };
    const onMessageEdited = (data: { message: Message }) => {
      if (isAuthorizedLoadedChannel(data.message.channelId)) addMessage(data.message.channelId, data.message);
    };
    const onMessageDeleted = (data: { messageId: string; channelId: string; event?: Message }) => {
      if (!isAuthorizedLoadedChannel(data.channelId)) return;
      if (data.event) addMessage(data.channelId, data.event);
      else removeMessage(data.messageId, data.channelId);
      const workspaceId = useWorkspaceStore.getState().activeWorkspaceId;
      if (workspaceId) void loadWorkspaceState(workspaceId);
    };
    const onReactionUpdated = (data: { messageId: string; channelId: string; reactions: Reaction[] }) => {
      if (isAuthorizedLoadedChannel(data.channelId)) applyReactionUpdate(data.channelId, data.messageId, data.reactions);
    };
    const onPinUpdated = (data: { messageId: string; channelId: string; pinned: boolean }) => {
      if (isAuthorizedLoadedChannel(data.channelId)) applyPinUpdate(data.channelId, data.messageId, data.pinned);
    };
    const onAttachmentCreated = (attachment: Attachment) => {
      if (!isAuthorizedLoadedChannel(attachment.channelId || '')) return;
      applyAttachment(attachment.channelId!, attachment);
    };
    const onDmCreated = (data: { dm: DirectMessageConversation }) => {
      upsertDm(data.dm);
      if (data.dm.workspaceId === useWorkspaceStore.getState().activeWorkspaceId) void loadChannels(data.dm.workspaceId);
    };
    const onReadUpdated = (position: ReadPosition) => {
      if (position.userId === userId && isAuthorizedLoadedChannel(position.channelId)) applySocketReadPosition(position);
    };
    const onDeviceRegistered = (device: Device) => {
      if (device.userId !== userId) return;
      try {
        if (device.id === getActiveDevice().deviceId) return;
      } catch {
        return;
      }
      const workspaceId = useWorkspaceStore.getState().activeWorkspaceId;
      if (workspaceId) syncLoadedWorkspaceKeys(workspaceId);
    };
    const onWorkspaceMembershipChanged = (value: unknown) => {
      const data = parseWorkspaceAuthorizationRefresh(value);
      if (data) {
        useUiStore.getState().noteAuthorizationChange();
        enqueueAuthorizationWork(() => refreshWorkspaceAuthorization(data.workspaceId));
      }
    };
    const onWorkspaceKeyStateDirty = (value: unknown) => {
      const data = parseWorkspaceAuthorizationRefresh(value);
      if (data) syncLoadedWorkspaceKeys(data.workspaceId);
    };
    const onWorkspaceAccessRevoked = (value: unknown) => {
      const data = parseWorkspaceAccessRevokedEvent(value);
      if (!data) return;
      // Start scope invalidation synchronously, outside the serialized refresh
      // queue, so a slow prior list request cannot keep plaintext visible.
      const cleanup = clearWorkspaceSecurityScope(data.workspaceId, data.channelIds);
      enqueueAuthorizationWork(async () => {
        await cleanup;
        const workspaces = await loadWorkspaces();
        if (workspaces && !useWorkspaceStore.getState().error) await selectReplacementWorkspace();
      });
    };
    const onChannelPermissionsUpdated = (value: unknown) => {
      const data = parseChannelAuthorizationEvent(value);
      if (data) {
        useUiStore.getState().noteAuthorizationChange();
        enqueueAuthorizationWork(() => refreshWorkspaceAuthorization(data.workspaceId));
      }
    };
    const onChannelAccessRemoved = (value: unknown) => {
      const data = parseChannelAuthorizationEvent(value);
      if (!data) return;
      const cleanup = clearChannelSecurityScope(data.workspaceId, data.channelId);
      enqueueAuthorizationWork(async () => {
        await cleanup;
        if (useWorkspaceStore.getState().activeWorkspaceId === data.workspaceId) {
          await refreshWorkspaceAuthorization(data.workspaceId);
        }
      });
    };
    const onChannelRecipientsChanged = (value: unknown) => {
      if (typeof value !== 'object' || value === null) return;
      const channelId = (value as { channelId?: unknown }).channelId;
      if (typeof channelId === 'string') {
        useUiStore.getState().noteAuthorizationChange();
        scheduleKeySync([channelId]);
      }
    };
    const onPresenceChanged = (data: { userId: string; status: UserStatusType }) => setStatus(data.userId, data.status);
    const onTypingUpdate = (data: { channelId: string; userId: string; isTyping: boolean }) => {
      if (isAuthorizedLoadedChannel(data.channelId)) setTyping(data.channelId, data.userId, data.isTyping);
    };

    const rejoinActiveChannel = (attempt = 0) => {
      const workspaceId = useWorkspaceStore.getState().activeWorkspaceId;
      const channelState = useChannelStore.getState();
      const channelId = channelState.activeChannelId;
      if (disposed || !workspaceId || channelState.workspaceId !== workspaceId || !channelId || !socket.connected) return;
      socket.timeout(3000).emit('channel:join', channelId, (error: Error | null, result?: { ok: boolean }) => {
        if (disposed) return;
        if (!error && result?.ok) {
          void loadMessages(channelId);
        } else if (attempt < 2 && socket.connected) {
          rejoinTimer = setTimeout(() => rejoinActiveChannel(attempt + 1), 500 * (attempt + 1));
        }
      });
    };
    const onConnect = () => {
      if (rejoinTimer) clearTimeout(rejoinTimer);
      rejoinTimer = setTimeout(() => {
        enqueueAuthorizationWork(async () => {
          if (!await reconcileWorkspaceMembership()) return;
          rejoinActiveChannel();
          await flushOutbox();
          resumeFailedUploads();
        });
      }, 100);
    };

    socket.on('connect', onConnect);
    socket.on('message:new', onMessageNew);
    socket.on('message:edited', onMessageEdited);
    socket.on('message:deleted', onMessageDeleted);
    socket.on('message:reaction', onReactionUpdated);
    socket.on('message:pinned', onPinUpdated);
    socket.on('attachment:created', onAttachmentCreated);
    socket.on('dm:created', onDmCreated);
    socket.on('presence:changed', onPresenceChanged);
    socket.on('typing:update', onTypingUpdate);
    socket.on('read:updated', onReadUpdated);
    socket.on('device:registered', onDeviceRegistered);
    socket.on('workspace:member-added', onWorkspaceMembershipChanged);
    socket.on('workspace:roles-changed', onWorkspaceMembershipChanged);
    socket.on('workspace:permissions-updated', onWorkspaceMembershipChanged);
    socket.on('workspace:key-state-dirty', onWorkspaceKeyStateDirty);
    socket.on('workspace:access-revoked', onWorkspaceAccessRevoked);
    socket.on('channel:permissions-updated', onChannelPermissionsUpdated);
    socket.on('channel:access-revoked', onChannelAccessRemoved);
    socket.on('channel:deleted', onChannelAccessRemoved);
    socket.on('channel:member-added', onChannelRecipientsChanged);
    socket.on('channel:key-rotation-required', onChannelRecipientsChanged);
    // Authentication initializes the socket just before this protected layout
    // mounts. If the handshake already completed, run the same reconciliation
    // path instead of waiting for a future reconnect.
    if (socket.connected) onConnect();

    return () => {
      disposed = true;
      pendingKeySyncIds.clear();
      if (rejoinTimer) clearTimeout(rejoinTimer);
      socket.off('connect', onConnect);
      socket.off('message:new', onMessageNew);
      socket.off('message:edited', onMessageEdited);
      socket.off('message:deleted', onMessageDeleted);
      socket.off('message:reaction', onReactionUpdated);
      socket.off('message:pinned', onPinUpdated);
      socket.off('attachment:created', onAttachmentCreated);
      socket.off('dm:created', onDmCreated);
      socket.off('presence:changed', onPresenceChanged);
      socket.off('typing:update', onTypingUpdate);
      socket.off('read:updated', onReadUpdated);
      socket.off('device:registered', onDeviceRegistered);
      socket.off('workspace:member-added', onWorkspaceMembershipChanged);
      socket.off('workspace:roles-changed', onWorkspaceMembershipChanged);
      socket.off('workspace:permissions-updated', onWorkspaceMembershipChanged);
      socket.off('workspace:key-state-dirty', onWorkspaceKeyStateDirty);
      socket.off('workspace:access-revoked', onWorkspaceAccessRevoked);
      socket.off('channel:permissions-updated', onChannelPermissionsUpdated);
      socket.off('channel:access-revoked', onChannelAccessRemoved);
      socket.off('channel:deleted', onChannelAccessRemoved);
      socket.off('channel:member-added', onChannelRecipientsChanged);
      socket.off('channel:key-rotation-required', onChannelRecipientsChanged);
    };
  }, [addMessage, applyAttachment, applyPinUpdate, applyReactionUpdate, applySocketReadPosition,
    flushOutbox, loadChannels, loadMembers, loadMessages, loadWorkspaces, loadWorkspaceState,
    noteBaseMessage, removeMessage, resumeFailedUploads, setActiveWorkspace, setStatus, setTyping,
    upsertDm, userId]);
}
