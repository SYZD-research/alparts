import { deletePersistedChannelKeys } from '../services/crypto.service';
import { useAttachmentStore } from './attachment.store';
import { useChannelStore } from './channel.store';
import { useDmStore } from './dm.store';
import { useDraftStore } from './draft.store';
import { useMessageStore } from './message.store';
import { useForumStore } from './forum.store';
import { useOutboxStore } from './outbox.store';
import { usePresenceStore } from './presence.store';
import { useUiStore } from './ui.store';
import { useUserStateStore } from './user-state.store';
import { useWorkspaceStore } from './workspace.store';
import { useVoiceStore } from './voice.store';
import { useAttentionStore } from './attention.store';

/**
 * Remove plaintext, authenticated runtime state, encrypted local queues and
 * this active device's persisted wrapped channel keys for exactly one channel.
 * Persistent deletion is best-effort: remote erasure of browser storage is
 * outside the platform guarantee, but no failure restores in-memory state.
 */
export async function clearChannelSecurityScope(workspaceId: string, channelId: string): Promise<void> {
  if (useVoiceStore.getState().channelId === channelId) useVoiceStore.getState().leave();
  useVoiceStore.getState().clearChannelParticipants(channelId);
  useAttentionStore.getState().clearChannel(channelId);
  // Calling this first synchronously blocks late ensure/get key work before
  // any plaintext store teardown yields to the event loop.
  const keyDeletion = deletePersistedChannelKeys(channelId);
  // Clear channel-indexed user operations while message ids are still
  // available to invalidate pending bookmark requests.
  useUserStateStore.getState().clearChannel(workspaceId, channelId);
  useForumStore.getState().clearChannel(channelId);
  useMessageStore.getState().clearChannel(channelId);
  useAttachmentStore.getState().clearChannel(channelId);
  usePresenceStore.getState().clearChannel(channelId);
  useDmStore.getState().clearChannel(channelId);
  useChannelStore.getState().removeChannel(channelId, workspaceId);
  // A permission-preview dialog can retain target/member metadata even after
  // its channel disappears from the backing store. Close it immediately.
  useUiStore.getState().closeChannelManager();

  const draftDeletion = useDraftStore.getState().clearChannel(channelId);
  const outboxDeletion = useOutboxStore.getState().clearChannel(channelId);
  await Promise.allSettled([
    draftDeletion,
    outboxDeletion,
    keyDeletion,
  ]);
}

/** Remove only one revoked workspace while preserving unrelated workspace state. */
export async function clearWorkspaceSecurityScope(
  workspaceId: string,
  hintedChannelIds: readonly string[] = [],
): Promise<void> {
  const channelState = useChannelStore.getState();
  const userState = useUserStateStore.getState();
  const dmState = useDmStore.getState();
  const channelIds = new Set<string>([
    ...hintedChannelIds,
    ...Object.keys(userState.channelStatesByWorkspace[workspaceId] || {}),
    ...(channelState.workspaceId === workspaceId ? channelState.channels.map((channel) => channel.id) : []),
    ...(dmState.conversationsByWorkspace[workspaceId] || []).map((conversation) => conversation.channelId),
  ]);
  // Every call performs its memory/key-scope invalidation synchronously before
  // yielding. Start all of them before waiting on slower IndexedDB deletion.
  const channelCleanups = [...channelIds].map((channelId) => (
    clearChannelSecurityScope(workspaceId, channelId)
  ));
  useDmStore.getState().clearWorkspace(workspaceId);
  useUserStateStore.getState().clearWorkspace(workspaceId);
  const wasActive = useWorkspaceStore.getState().activeWorkspaceId === workspaceId;
  useWorkspaceStore.getState().removeWorkspace(workspaceId);
  if (wasActive) {
    useUiStore.getState().closeChannelManager();
    useUiStore.getState().closeWorkspaceManager();
    useUiStore.getState().closeSavedMessages();
    useUiStore.getState().closeDmComposer();
  }
  await Promise.allSettled(channelCleanups);
}
