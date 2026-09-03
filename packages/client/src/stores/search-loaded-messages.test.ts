import { describe, expect, it } from 'vitest';
import { searchLoadedMessages, type SearchableLoadedMessage } from './search-loaded-messages';

function message(overrides: Partial<SearchableLoadedMessage>): SearchableLoadedMessage {
  return {
    id: 'message-1',
    channelId: 'channel-1',
    type: 'message',
    content: 'Release checklist',
    createdAt: '2026-01-01T00:00:00.000Z',
    author: { displayName: 'Konoha' },
    ...overrides,
  };
}

describe('searchLoadedMessages', () => {
  it('searches only loaded decrypted content and omits deleted or security-marker messages', () => {
    const result = searchLoadedMessages('release', {
      'channel-1': [
        message({ id: 'valid' }),
        message({ id: 'deleted', type: 'delete' }),
        message({ id: 'unavailable', content: '[メッセージを検証できませんでした]' }),
      ],
      'not-current-workspace': [message({ id: 'stale', channelId: 'not-current-workspace' })],
    }, [{ id: 'channel-1', name: 'general' }]);

    expect(result.map((item) => item.messageId)).toEqual(['valid']);
  });

  it('normalizes case and full-width characters and ranks content before metadata', () => {
    const result = searchLoadedMessages('ＡＬＰＡＲＴＳ', {
      'channel-1': [
        message({ id: 'metadata', content: 'unrelated', author: { displayName: 'Alparts team' } }),
        message({ id: 'content', content: 'alparts launch', createdAt: '2025-01-01T00:00:00.000Z' }),
      ],
    }, [{ id: 'channel-1', name: 'general' }]);

    expect(result.map((item) => item.messageId)).toEqual(['content', 'metadata']);
  });
});
