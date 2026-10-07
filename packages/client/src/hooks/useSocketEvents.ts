import { useEffect } from 'react';
import type { Attachment, Device, Message, Reaction, ReadPosition, UserStatusType } from '@alparts/shared';
import { getActiveDevice } from '../services/crypto.service';
import { onChannelGroupAdvanced, scheduleGroupMaintenance } from '../services/mls-group.service';
import { getSocket } from '../services/socket';
import type { DirectMessageConversation } from '../services/api';
import { api } from '../services/api';
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
import { parseAttentionNotification } from '../services/attention-model';
import { useAttentionStore } from '../stores/attention.store';
import { useForumStore } from '../stores/forum.store';
import {
  parseForumPostRef,
  parseForumPostUpdated,
  parseForumTagsUpdated,
} from '../stores/forum-model';

export function useSocketEvents() {
  const addMessages = useMessageStore((state) => state.addMessages);
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
  const addAttention = useAttentionStore((state) => state.add);

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    let rejoinTimer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    let authorizationQueue = Promise.resolve();
    let authorizationQueueDepth = 0;
    const pendingKeySyncIds = new Set<string>();
    let keySyncRunning = false;
    const pendingMessages = new Map<string, Message[]>();
    let messageFlushScheduled = false;
    const maxPendingAuthorizationTasks = 64;

    const isAuthorizedLoadedChannel = (channelId: string) => (
      useChannelStore.getState().channels.some((channel) => channel.id === channelId)
      && (
        Object.prototype.hasOwnProperty.call(useMessageStore.getState().eventsByChannel, channelId)
        || useMessageStore.getState().loadingByChannel[channelId] === true
      )
    );
    const isAuthorizedKeySyncChannel = (channelId: string) => {
      const channel = useChannelStore.getState().channels.find((candidate) => candidate.id === channelId);
      return Boolean(channel && channel.type !== 'voice');
    };

    let authorizationResyncRequired = false;
    const enqueueAuthorizationWork = (operation: () => Promise<void>) => {
      // Revocation handlers erase the affected security scope before entering
      // this queue. At the cap, individual events are coalesced into one full
      // refresh of the active workspace once the queue drains, so no event is
      // silently lost until the next reload.
      if (authorizationQueueDepth >= maxPendingAuthorizationTasks) {
        authorizationResyncRequired = true;
        return;
      }
      authorizationQueueDepth += 1;
      authorizationQueue = authorizationQueue
        .catch(() => undefined)
        .then(async () => {
          if (!disposed) await operation();
        })
        .catch(() => undefined)
        .finally(() => {
          authorizationQueueDepth -= 1;
          if (authorizationQueueDepth === 0 && authorizationResyncRequired && !disposed) {
            authorizationResyncRequired = false;
            enqueueAuthorizationWork(async () => {
              const workspaceId = useWorkspaceStore.getState().activeWorkspaceId;
              await loadWorkspaces();
              if (workspaceId) await refreshWorkspaceAuthorization(workspaceId);
            });
          }
        });
    };

    const scheduleKeySync = (channelIds: string[]) => {
      for (const channelId of channelIds) {
        // Channels of the shown workspace catch up even before they are
        // opened, so sending later does not wait for it.
        if (isAuthorizedKeySyncChannel(channelId)) pendingKeySyncIds.add(channelId);
      }
      if (keySyncRunning || pendingKeySyncIds.size === 0) return;
      keySyncRunning = true;
      void (async () => {
        while (!disposed && pendingKeySyncIds.size > 0) {
          const channelId = pendingKeySyncIds.values().next().value as string;
          pendingKeySyncIds.delete(channelId);
          if (!isAuthorizedKeySyncChannel(channelId)) continue;
          try {
            await useMessageStore.getState().retryChannelPreparation(channelId);
          } catch {
            // Another device may add this one later. Missing or revoked keys
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
      const refreshed = await loadChannels(workspaceId);
      const after = useChannelStore.getState();
      if (!refreshed || disposed || after.workspaceId !== workspaceId || after.error) return;

      // Only a successfully applied authorization list can prove revocation.
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

    const flushMessages = () => {
      messageFlushScheduled = false;
      for (const [channelId, messages] of pendingMessages) {
        if (disposed || !isAuthorizedLoadedChannel(channelId)) continue;
        addMessages(channelId, messages);
        for (const message of messages) noteBaseMessage(message);
      }
      pendingMessages.clear();
    };
    const enqueueMessage = (message: Message) => {
      if (!isAuthorizedLoadedChannel(message.channelId)) return;
      const pending = pendingMessages.get(message.channelId) ?? [];
      pending.push(message);
      pendingMessages.set(message.channelId, pending);
      if (pending.length >= 64) flushMessages();
      else if (!messageFlushScheduled) {
        messageFlushScheduled = true;
        queueMicrotask(flushMessages);
      }
    };
    const onMessageNew = (data: { message: Message }) => {
      enqueueMessage(data.message);
    };
    const onMessageEdited = (data: { message: Message }) => {
      enqueueMessage(data.message);
    };
    const onMessageDeleted = (data: { messageId: string; channelId: string; event?: Message }) => {
      if (!isAuthorizedLoadedChannel(data.channelId)) return;
      if (data.event) enqueueMessage(data.event);
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
    const onForumPostUpdated = (value: unknown) => {
      const state = parseForumPostUpdated(value);
      if (state && isAuthorizedLoadedChannel(state.channelId)) useForumStore.getState().applyPostState(state);
    };
    const onForumPostRemoved = (value: unknown) => {
      const data = parseForumPostRef(value);
      if (data && isAuthorizedLoadedChannel(data.channelId)) useForumStore.getState().removePost(data.channelId, data.postId);
    };
    const onForumPostRead = (value: unknown) => {
      const data = parseForumPostRef(value);
      const at = (value as { lastReadActivityAt?: unknown } | null)?.lastReadActivityAt;
      if (data && typeof at === 'string' && Number.isFinite(Date.parse(at)) && isAuthorizedLoadedChannel(data.channelId)) {
        useForumStore.getState().applyPostRead(data.channelId, data.postId, at);
      }
    };
    const onForumTagsUpdated = (value: unknown) => {
      const data = parseForumTagsUpdated(value);
      if (data && isAuthorizedLoadedChannel(data.channelId)) useForumStore.getState().applyTags(data.channelId, data.tags);
    };
    const onDmCreated = (data: { dm: DirectMessageConversation }) => {
      upsertDm(data.dm);
      if (data.dm.workspaceId === useWorkspaceStore.getState().activeWorkspaceId) {
        void loadChannels(data.dm.workspaceId).then(() => scheduleKeySync([data.dm.channelId]));
      }
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
      useUiStore.getState().openAccountSecurity();
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
      if (!data) return;
      scheduleGroupMaintenance();
      syncLoadedWorkspaceKeys(data.workspaceId);
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
        // Channels of every workspace: publish this device's package, or add
        // devices that are waiting, without loading any messages.
        scheduleGroupMaintenance();
        scheduleKeySync([channelId]);
      }
    };
    const onPresenceChanged = (data: { userId: string; status: UserStatusType }) => setStatus(data.userId, data.status);
    // Profile (name, picture, self-introduction) or warning changes: refresh
    // the member list of the workspace being shown.
    const onMemberProfileChanged = (value: unknown) => {
      if (typeof value !== 'object' || value === null) return;
      const { workspaceId, userId: changedUserId } = value as { workspaceId?: unknown; userId?: unknown };
      if (typeof workspaceId !== 'string') return;
      if (workspaceId === useWorkspaceStore.getState().activeWorkspaceId) void loadMembers(workspaceId);
      if (changedUserId === userId) {
        void api.getMe().then((me) => {
          const current = useAuthStore.getState().user;
          if (current && current.id === me.id) useAuthStore.setState({ user: me });
        }).catch(() => undefined);
      }
    };
    const onTypingUpdate = (data: { channelId: string; userId: string; isTyping: boolean }) => {
      if (isAuthorizedLoadedChannel(data.channelId)) setTyping(data.channelId, data.userId, data.isTyping);
    };
    const onAttention = (value: unknown) => {
      const notification = parseAttentionNotification(value);
      if (!notification) return;
      // Managers are told about a restarted channel even when they cannot see
      // it; a profile appeal concerns a member, not a channel.
      if (notification.kind === 'channel-restarted' || notification.kind === 'profile-appeal' || notification.channelId === null) {
        addAttention(notification);
        return;
      }
      const channelId = notification.channelId;
      const state = useUserStateStore.getState();
      if (Object.prototype.hasOwnProperty.call(state.channelStatesByWorkspace, notification.workspaceId)) {
        if (state.channelStatesByWorkspace[notification.workspaceId]?.[channelId]) {
          addAttention(notification);
        }
        return;
      }
      void loadWorkspaceState(notification.workspaceId).then((channelStates) => {
        if (channelStates[channelId]) addAttention(notification);
      });
    };

    const rejoinActiveChannel = (attempt = 0) => {
      const workspaceId = useWorkspaceStore.getState().activeWorkspaceId;
      const channelState = useChannelStore.getState();
      const channelId = channelState.activeChannelId;
      if (disposed || !workspaceId || channelState.workspaceId !== workspaceId || !channelId || !socket.connected) return;
      socket.timeout(3000).emit('channel:join', channelId, (error: Error | null, result?: { ok: boolean }) => {
        if (disposed || useChannelStore.getState().activeChannelId !== channelId) return;
        if (!error && result?.ok) {
          void loadMessages(channelId);
          // A forum on screen missed live updates while disconnected.
          void useForumStore.getState().refreshChannel(channelId);
        } else if (socket.connected) {
          void loadMessages(channelId);
          rejoinTimer = setTimeout(() => rejoinActiveChannel(attempt + 1), Math.min(30_000, 500 * 2 ** Math.min(attempt, 6)));
        }
      });
    };
    const onConnect = () => {
      if (rejoinTimer) clearTimeout(rejoinTimer);
      rejoinTimer = setTimeout(() => {
        enqueueAuthorizationWork(async () => {
          if (!await reconcileWorkspaceMembership()) return;
          rejoinActiveChannel();
          scheduleGroupMaintenance();
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
    socket.on('forum:post-updated', onForumPostUpdated);
    socket.on('forum:post-removed', onForumPostRemoved);
    socket.on('forum:post-read', onForumPostRead);
    socket.on('forum:tags-updated', onForumTagsUpdated);
    socket.on('attachment:created', onAttachmentCreated);
    socket.on('dm:created', onDmCreated);
    socket.on('presence:changed', onPresenceChanged);
    socket.on('member:profile-updated', onMemberProfileChanged);
    socket.on('workspace:profile-flags-changed', onMemberProfileChanged);
    socket.on('typing:update', onTypingUpdate);
    socket.on('read:updated', onReadUpdated);
    socket.on('attention:new', onAttention);
    const onAccountSecurityChanged = () => useUiStore.getState().openAccountSecurity();
    socket.on('account:security-changed', onAccountSecurityChanged);
    socket.on('device:revoked', onAccountSecurityChanged);
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
    const unsubscribeChannelList = useChannelStore.subscribe((state, previous) => {
      if (
        state.workspaceId
        && (state.workspaceId !== previous.workspaceId || state.channels !== previous.channels)
      ) {
        // A loaded channel list may show channels this device has no package
        // for yet, in any workspace.
        scheduleGroupMaintenance();
        syncLoadedWorkspaceKeys(state.workspaceId);
      }
    });
    // Messages of a channel refused for an older key go out once this device
    // has a newer one; other refusals wait for a retry or a reconnect.
    let outboxFlushTimer: ReturnType<typeof setTimeout> | undefined;
    const advancedChannels = new Set<string>();
    const unsubscribeGroupAdvance = onChannelGroupAdvanced((channelId) => {
      advancedChannels.add(channelId);
      if (outboxFlushTimer) return;
      outboxFlushTimer = setTimeout(() => {
        outboxFlushTimer = undefined;
        const channelIds = [...advancedChannels];
        advancedChannels.clear();
        if (!disposed) void useOutboxStore.getState().flushKeyRefusals(channelIds);
      }, 250);
    });
    // Authentication initializes the socket just before this protected layout
    // mounts. If the handshake already completed, run the same reconciliation
    // path instead of waiting for a future reconnect.
    if (socket.connected) onConnect();

    return () => {
      disposed = true;
      pendingMessages.clear();
      pendingKeySyncIds.clear();
      if (rejoinTimer) clearTimeout(rejoinTimer);
      socket.off('connect', onConnect);
      socket.off('message:new', onMessageNew);
      socket.off('message:edited', onMessageEdited);
      socket.off('message:deleted', onMessageDeleted);
      socket.off('message:reaction', onReactionUpdated);
      socket.off('message:pinned', onPinUpdated);
      socket.off('forum:post-updated', onForumPostUpdated);
      socket.off('forum:post-removed', onForumPostRemoved);
      socket.off('forum:post-read', onForumPostRead);
      socket.off('forum:tags-updated', onForumTagsUpdated);
      socket.off('attachment:created', onAttachmentCreated);
      socket.off('dm:created', onDmCreated);
      socket.off('presence:changed', onPresenceChanged);
      socket.off('member:profile-updated', onMemberProfileChanged);
      socket.off('workspace:profile-flags-changed', onMemberProfileChanged);
      socket.off('typing:update', onTypingUpdate);
      socket.off('read:updated', onReadUpdated);
      socket.off('attention:new', onAttention);
      socket.off('account:security-changed', onAccountSecurityChanged);
      socket.off('device:revoked', onAccountSecurityChanged);
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
      unsubscribeChannelList();
      unsubscribeGroupAdvance();
      if (outboxFlushTimer) clearTimeout(outboxFlushTimer);
    };
  }, [addAttention, addMessages, applyAttachment, applyPinUpdate, applyReactionUpdate, applySocketReadPosition,
    flushOutbox, loadChannels, loadMembers, loadMessages, loadWorkspaces, loadWorkspaceState,
    noteBaseMessage, removeMessage, resumeFailedUploads, setActiveWorkspace, setStatus, setTyping,
    upsertDm, userId]);
}
