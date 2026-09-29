import { describe, expect, it } from 'vitest';
import { attentionNotificationKey, parseAttentionNotification } from './attention-model';

const notification = {
  notificationId: '00000000-0000-4000-8000-000000000001',
  workspaceId: '00000000-0000-4000-8000-000000000002',
  channelId: '00000000-0000-4000-8000-000000000003',
  kind: 'reply' as const,
};

describe('attention notification model', () => {
  it('accepts content-free notifications and rejects unexpected content', () => {
    expect(parseAttentionNotification(notification)).toEqual(notification);
    expect(attentionNotificationKey(notification)).toBe(`${notification.notificationId}:reply`);
    expect(parseAttentionNotification({ ...notification, message: 'secret body' })).toBeNull();
    expect(parseAttentionNotification({ ...notification, kind: 'all' })).toBeNull();
    const restarted = { ...notification, kind: 'channel-restarted' as const };
    expect(parseAttentionNotification(restarted)).toEqual(restarted);
  });
});
