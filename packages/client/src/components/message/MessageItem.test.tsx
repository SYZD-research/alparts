import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { Message } from '@alparts/shared';
import { MessageItem } from './MessageItem';
import { canSwipeMessage, messageSwipeAction } from './message-swipe-model';
import { markMessageCryptoVerification, markMessageKeyUnavailable } from '../../stores/message-projector';

describe('MessageItem reply presentation', () => {
  it('places the main avatar below the reply preview and omits reply-count UI', () => {
    const html = renderToStaticMarkup(
      <MessageItem message={replyMessage()} isFirst onJumpToMessage={() => undefined} />,
    );

    expect(html).toContain('aria-label="返信先のメッセージへ移動"');
    expect(html).toContain('mt-6');
    expect(html).not.toContain('件の返信');
  });
});

describe('message swipe actions', () => {
  it('replies at 64 pixels and edits an own message at 136 pixels', () => {
    expect(messageSwipeAction(-63, true)).toBeNull();
    expect(messageSwipeAction(-64, true)).toBe('reply');
    expect(messageSwipeAction(-135, true)).toBe('reply');
    expect(messageSwipeAction(-136, true)).toBe('edit');
    expect(messageSwipeAction(-220, false)).toBe('reply');
    expect(messageSwipeAction(180, true)).toBeNull();
  });

  it('chooses the current release action when returning from the edit threshold', () => {
    expect(messageSwipeAction(-180, true)).toBe('edit');
    expect(messageSwipeAction(-90, true)).toBe('reply');
    expect(messageSwipeAction(-20, true)).toBeNull();
  });

  it('excludes deleted, reaction, unavailable, and verification-failed messages', () => {
    const message = replyMessage();
    expect(canSwipeMessage(message)).toBe(true);
    expect(canSwipeMessage({ ...message, type: 'edit' })).toBe(true);
    expect(canSwipeMessage({ ...message, type: 'delete' })).toBe(false);
    expect(canSwipeMessage({ ...message, type: 'reaction' })).toBe(false);
    expect(canSwipeMessage({ ...message, content: '[表示できないメッセージ]' })).toBe(false);
    expect(canSwipeMessage(markMessageCryptoVerification(message, false))).toBe(false);
    expect(canSwipeMessage(markMessageKeyUnavailable(message))).toBe(false);
  });
});

function replyMessage(): Message {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    channelId: '00000000-0000-4000-8000-000000000002',
    authorId: '00000000-0000-4000-8000-000000000003',
    author: {
      id: '00000000-0000-4000-8000-000000000003',
      displayName: 'miso',
      avatarUrl: null,
      status: 'online',
      createdAt: '2026-09-03T09:32:00.000Z',
    },
    deviceId: '00000000-0000-4000-8000-000000000004',
    content: 'これ。',
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type: 'message',
    refMessageId: '00000000-0000-4000-8000-000000000005',
    reactions: [],
    isPinned: false,
    idempotencyKey: 'reply-layout-test',
    createdAt: '2026-09-03T09:32:00.000Z',
  };
}
