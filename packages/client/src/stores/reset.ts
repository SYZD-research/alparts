import { clearLocalStateSession } from '../services/local-state.service';
import { useChannelStore } from './channel.store';
import { useDraftStore } from './draft.store';
import { useDmStore } from './dm.store';
import { useMessageStore } from './message.store';
import { useOutboxStore } from './outbox.store';
import { usePresenceStore } from './presence.store';
import { useWorkspaceStore } from './workspace.store';
import { useUiStore } from './ui.store';
import { useUserStateStore } from './user-state.store';
import { useAttachmentStore } from './attachment.store';
import { useVoiceStore } from './voice.store';

/** Remove all decrypted and authentication-scoped in-memory state. */
export function resetAuthenticatedState(): void {
  useVoiceStore.getState().reset();
  useAttachmentStore.getState().reset();
  useDraftStore.getState().reset();
  useDmStore.getState().reset();
  useOutboxStore.getState().reset();
  useUserStateStore.getState().reset();
  useMessageStore.getState().reset();
  usePresenceStore.getState().reset();
  useChannelStore.getState().reset();
  useWorkspaceStore.getState().reset();
  useUiStore.getState().reset();
  clearLocalStateSession();
}
