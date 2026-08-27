export interface SearchableLoadedMessage {
  id: string;
  channelId: string;
  type: string;
  content: string;
  createdAt: string;
  author?: { displayName?: string };
}
export interface LoadedMessageSearchResult {
  messageId: string;
  channelId: string;
  channelName: string;
  authorName: string;
  content: string;
  createdAt: string;
  score: number;
}

const NON_CONTENT_MARKERS = new Set([
  '[未検証の旧形式メッセージ]',
  '[署名検証に失敗したメッセージ]',
  '[復号鍵を利用できません]',
  '[改ざんを検出しました]',
]);

function normalized(value: string): string {
  return value.normalize('NFKC').toLocaleLowerCase();
}

/** Search only the decrypted messages already held in memory. */
export function searchLoadedMessages(
  query: string,
  messagesByChannel: Record<string, SearchableLoadedMessage[]>,
  channels: Array<{ id: string; name: string }>,
  limit = 50,
): LoadedMessageSearchResult[] {
  const needle = normalized(query.trim());
  if (!needle || limit <= 0) return [];
  const channelNames = new Map(channels.map((channel) => [channel.id, channel.name]));
  const results: LoadedMessageSearchResult[] = [];

  for (const [channelId, messages] of Object.entries(messagesByChannel)) {
    const channelName = channelNames.get(channelId);
    if (!channelName) continue;
    for (const message of messages) {
      if (
        (message.type !== 'message' && message.type !== 'edit' && message.type !== 'system')
        || !message.content
        || NON_CONTENT_MARKERS.has(message.content)
      ) continue;
      const content = normalized(message.content);
      const authorName = message.author?.displayName || '不明なユーザー';
      const author = normalized(authorName);
      const channel = normalized(channelName);
      const contentIndex = content.indexOf(needle);
      const matchesMetadata = author.includes(needle) || channel.includes(needle);
      if (contentIndex < 0 && !matchesMetadata) continue;
      const score = contentIndex === 0 ? 3 : contentIndex > 0 ? 2 : 1;
      results.push({
        messageId: message.id,
        channelId,
        channelName,
        authorName,
        content: message.content,
        createdAt: message.createdAt,
        score,
      });
    }
  }

  return results
    .sort((left, right) => (
      right.score - left.score
      || right.createdAt.localeCompare(left.createdAt)
      || left.messageId.localeCompare(right.messageId)
    ))
    .slice(0, limit);
}
