import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { Message } from '@alparts/shared';
import { MessageItem } from './MessageItem';

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
