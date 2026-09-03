import { describe, expect, it } from 'vitest';
import type { ChannelReadState, Message, User } from '@alparts/shared';
import {
  auditActionLabel,
  auditResult,
  auditTargetLabel,
  safeAuditDetails,
} from './audit-log-model';
import { insertPastedText, previewLargePaste } from './paste-preview-model';
import { buildMessagePermalink, parseMessageRoute, safeMessageReturnPath } from './permalink-model';
import { countLoadedThreadReplies, loadedThreadReplies } from './thread-model';
import { runBounded, summarizeWorkspaceUnread } from './workspace-unread-model';

const workspaceId = '00000000-0000-4000-8000-000000000001';
const channelId = '00000000-0000-4000-8000-000000000002';
const messageId = '00000000-0000-4000-8000-000000000003';

describe('permalink model', () => {
  it('builds and parses UUID-only message routes', () => {
    const path = buildMessagePermalink({ workspaceId, channelId, messageId });
    expect(path).toBe(`/workspaces/${workspaceId}/channels/${channelId}/messages/${messageId}`);
    expect(parseMessageRoute(path || '')).toEqual({ kind: 'message', workspaceId, channelId, messageId });
  });

  it('rejects malformed message routes without claiming unrelated workspace paths', () => {
    expect(parseMessageRoute('/workspaces/settings')).toEqual({ kind: 'none' });
    expect(parseMessageRoute(`/workspaces/${workspaceId}/channels/${channelId}/messages/not-a-uuid`)).toEqual({ kind: 'invalid' });
    expect(buildMessagePermalink({ workspaceId, channelId, messageId: '../plaintext' })).toBeNull();
    expect(safeMessageReturnPath('//evil.example/workspaces')).toBe('/');
    expect(safeMessageReturnPath(`/workspaces/${workspaceId}/channels/${channelId}/messages/${messageId}`))
      .toBe(`/workspaces/${workspaceId}/channels/${channelId}/messages/${messageId}`);
  });
});

describe('large paste model', () => {
  it('requires confirmation at the byte or line threshold and keeps markup literal', () => {
    expect(previewLargePaste('x'.repeat(1999))).toBeNull();
    expect(previewLargePaste('x'.repeat(2000))).toMatchObject({ byteCount: 2000, lineCount: 1 });
    expect(previewLargePaste(Array.from({ length: 20 }, (_, index) => `<b>line ${index}</b>`).join('\n')))
      .toMatchObject({ lineCount: 20 });
    expect(previewLargePaste(`${'<img src=x onerror=alert(1)>'.repeat(80)}`)?.head).toContain('<img');
  });

  it('inserts confirmed text at the captured selection', () => {
    expect(insertPastedText('hello world', 'secure', 6, 11)).toBe('hello secure');
    expect(insertPastedText('abc', 'x', -20, 99)).toBe('x');
  });
});

describe('workspace unread model', () => {
  it('totals server unread state including muted and hidden channels without fabricating mentions', () => {
    const states: Record<string, ChannelReadState> = {
      first: channelState('first', 80, { muted: true }),
      second: channelState('second', 25, { hidden: true }),
    };
    expect(summarizeWorkspaceUnread(states, true, null)).toEqual({
      status: 'ready',
      total: 105,
      badge: '99+',
      mentionStatus: 'unknown',
    });
    expect(summarizeWorkspaceUnread(undefined, false, 'forbidden')).toMatchObject({ status: 'error', badge: '?' });
  });

  it('bounds concurrent workspace requests', async () => {
    let active = 0;
    let maximum = 0;
    await runBounded([1, 2, 3, 4, 5, 6], 2, async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      await new Promise<void>((resolve) => setTimeout(resolve, 1));
      active -= 1;
    });
    expect(maximum).toBe(2);
  });
});

describe('audit details model', () => {
  it('shows only useful labeled details and never dumps identifiers, internal values, secrets, or nested values', () => {
    const details = {
      workspaceId,
      result: 'failure',
      reason: 'forbidden',
      token: 'top-secret',
      hash: 'chain-value',
      unknownField: 'do not render',
      changed: true,
      nested: { password: 'hidden' },
    };
    expect(safeAuditDetails(details)).toEqual([
      { key: '変更', value: 'あり' },
    ]);
    expect(auditResult({ details })).toBe('failure');
  });

  it('uses plain labels instead of internal audit action and target names', () => {
    expect(auditActionLabel('channel.key.epoch.propose')).toBe('チャンネルの利用準備を更新');
    expect(auditActionLabel('internal.unknown.operation')).toBe('管理操作');
    expect(auditTargetLabel('workspace_invitation')).toBe('招待');
    expect(auditTargetLabel('internal_target')).toBeNull();
  });
});

describe('loaded thread model', () => {
  it('counts and orders only loaded replies for the selected base message', () => {
    const root = message({ id: messageId, createdAt: '2026-01-01T00:00:00.000Z' });
    const earlier = message({ id: '00000000-0000-4000-8000-000000000004', refMessageId: root.id, createdAt: '2026-01-01T00:00:01.000Z' });
    const later = message({ id: '00000000-0000-4000-8000-000000000005', refMessageId: root.id, createdAt: '2026-01-01T00:00:02.000Z' });
    const other = message({ id: '00000000-0000-4000-8000-000000000006', refMessageId: 'other-root', createdAt: '2026-01-01T00:00:03.000Z' });
    const loaded = [later, other, root, earlier];
    expect(countLoadedThreadReplies(loaded)).toEqual({ [root.id]: 2, 'other-root': 1 });
    expect(loadedThreadReplies(loaded, root.id).map((item) => item.id)).toEqual([earlier.id, later.id]);
  });
});

function channelState(
  id: string,
  unreadCount: number,
  overrides: Partial<ChannelReadState> = {},
): ChannelReadState {
  return {
    channelId: id,
    favorite: false,
    muted: false,
    hidden: false,
    notificationLevel: 'all',
    updatedAt: '2026-01-01T00:00:00.000Z',
    lastReadMessageId: null,
    latestMessageId: messageId,
    unreadCount,
    ...overrides,
  };
}

const author: User = {
  id: '00000000-0000-4000-8000-000000000010',
  email: 'user@example.test',
  displayName: 'User',
  avatarUrl: null,
  status: 'online',
  createdAt: '2026-01-01T00:00:00.000Z',
};

function message(overrides: Pick<Message, 'id' | 'createdAt'> & Partial<Message>): Message {
  const { id, createdAt, ...rest } = overrides;
  return {
    id,
    channelId,
    authorId: author.id,
    author,
    deviceId: '00000000-0000-4000-8000-000000000011',
    content: 'loaded plaintext',
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type: 'message',
    refMessageId: null,
    reactions: [],
    isPinned: false,
    idempotencyKey: `idem-${id}`,
    createdAt,
    ...rest,
  };
}
