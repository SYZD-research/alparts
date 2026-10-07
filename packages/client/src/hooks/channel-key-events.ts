/** What the socket events about channels' group keys trigger. */
export interface ChannelKeyEventActions {
  noteAuthorizationChange: () => void;
  scheduleGroupMaintenance: () => void;
  scheduleKeySync: (channelIds: string[]) => void;
}

function eventChannelId(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null;
  const channelId = (value as { channelId?: unknown }).channelId;
  return typeof channelId === 'string' ? channelId : null;
}

/**
 * `channel:key-rotation-required`: a channel's group may need this device's
 * package or a commit. It arrives for every package and commit in every
 * channel the user sees, so it never counts as an authorization change.
 */
export function handleChannelKeyStateEvent(value: unknown, actions: ChannelKeyEventActions): void {
  const channelId = eventChannelId(value);
  if (!channelId) return;
  // Channels of every workspace: publish this device's package, or add
  // devices that are waiting, without loading any messages.
  actions.scheduleGroupMaintenance();
  actions.scheduleKeySync([channelId]);
}

/** `channel:member-added`: who may see the channel changed, and so may its group. */
export function handleChannelMemberAddedEvent(value: unknown, actions: ChannelKeyEventActions): void {
  if (!eventChannelId(value)) return;
  actions.noteAuthorizationChange();
  handleChannelKeyStateEvent(value, actions);
}
