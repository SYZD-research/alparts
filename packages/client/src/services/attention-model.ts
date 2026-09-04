import type { WsAttentionNotification } from '@alparts/shared';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function parseAttentionNotification(value: unknown): WsAttentionNotification | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const keys = Object.keys(candidate).sort();
  if (keys.join(',') !== 'channelId,kind,notificationId,workspaceId') return null;
  if (
    typeof candidate.notificationId !== 'string' || !UUID.test(candidate.notificationId)
    || typeof candidate.workspaceId !== 'string' || !UUID.test(candidate.workspaceId)
    || typeof candidate.channelId !== 'string' || !UUID.test(candidate.channelId)
    || (candidate.kind !== 'mention' && candidate.kind !== 'reply')
  ) return null;
  return candidate as unknown as WsAttentionNotification;
}

export function attentionNotificationKey(notification: WsAttentionNotification): string {
  return `${notification.notificationId}:${notification.kind}`;
}
