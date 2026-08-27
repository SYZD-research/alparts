const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MESSAGE_LINK = /^\/workspaces\/([^/]+)\/channels\/([^/]+)\/messages\/([^/]+)\/?$/;

export interface MessagePermalink {
  workspaceId: string;
  channelId: string;
  messageId: string;
}

export type ParsedMessageRoute =
  | { kind: 'none' }
  | { kind: 'invalid' }
  | ({ kind: 'message' } & MessagePermalink);

export function buildMessagePermalink(input: MessagePermalink): string | null {
  if (!UUID.test(input.workspaceId) || !UUID.test(input.channelId) || !UUID.test(input.messageId)) return null;
  return `/workspaces/${input.workspaceId}/channels/${input.channelId}/messages/${input.messageId}`;
}

export function parseMessageRoute(pathname: string): ParsedMessageRoute {
  if (!/^\/workspaces\/[^/]+\/channels\/[^/]+\/messages(?:\/|$)/.test(pathname)) return { kind: 'none' };
  const match = MESSAGE_LINK.exec(pathname);
  if (!match) return { kind: 'invalid' };
  const [workspaceId, channelId, messageId] = match.slice(1).map((value) => {
    try {
      return decodeURIComponent(value);
    } catch {
      return '';
    }
  });
  if (!UUID.test(workspaceId) || !UUID.test(channelId) || !UUID.test(messageId)) return { kind: 'invalid' };
  return { kind: 'message', workspaceId, channelId, messageId };
}

export function safeMessageReturnPath(value: unknown): string {
  return typeof value === 'string' && parseMessageRoute(value).kind === 'message' ? value : '/';
}
