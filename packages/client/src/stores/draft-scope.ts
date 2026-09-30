/**
 * A draft scope is a channel id, or `${channelId}:${postId}` for replies in a
 * forum post. Ids are UUIDs, so ':' only separates the two parts.
 */
export function forumPostDraftScope(channelId: string, postId: string): string {
  return `${channelId}:${postId}`;
}

export function draftScopeChannelId(scope: string): string {
  return scope.split(':', 1)[0]!;
}

export function draftScopeBelongsToChannel(scope: string, channelId: string): boolean {
  return scope === channelId || scope.startsWith(`${channelId}:`);
}
