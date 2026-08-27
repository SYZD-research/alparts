export const MAX_REVOKED_CHANNEL_HINTS = 1_000;

export interface WorkspaceAccessRevokedEvent {
  workspaceId: string;
  membershipRemoved: true;
  channelIds: string[];
}

export interface ChannelAuthorizationEvent {
  workspaceId: string;
  channelId: string;
}

export function parseWorkspaceAccessRevokedEvent(value: unknown): WorkspaceAccessRevokedEvent | null {
  if (!isRecord(value)
    || !isUuid(value.workspaceId)
    || value.membershipRemoved !== true) {
    return null;
  }
  // Membership removal is authoritative even if an optional hygiene hint is
  // malformed or oversized. Only bounded, individually valid UUIDs are used
  // as local deletion targets; the rest cannot suppress workspace cleanup.
  const boundedHints = Array.isArray(value.channelIds)
    ? value.channelIds.slice(0, MAX_REVOKED_CHANNEL_HINTS).filter(isUuid)
    : [];
  return {
    workspaceId: value.workspaceId,
    membershipRemoved: true,
    channelIds: [...new Set(boundedHints)],
  };
}

export function parseChannelAuthorizationEvent(value: unknown): ChannelAuthorizationEvent | null {
  if (!isRecord(value) || !isUuid(value.workspaceId) || !isUuid(value.channelId)) return null;
  return { workspaceId: value.workspaceId, channelId: value.channelId };
}

export function parseWorkspaceAuthorizationRefresh(value: unknown): { workspaceId: string } | null {
  if (!isRecord(value) || !isUuid(value.workspaceId) || value.membershipRemoved === true) return null;
  return { workspaceId: value.workspaceId };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
