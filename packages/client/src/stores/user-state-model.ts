import type {
  ChannelPreference,
  ChannelReadState,
  MessageBookmark,
} from '@alparts/shared';
import { messageMentionsCurrentUser } from '../services/mention-model';
import { TAMPERED_MESSAGE_MARKER, UNAVAILABLE_MESSAGE_MARKER, UNVERIFIED_MESSAGE_MARKER } from '../services/message-display';

export interface OrderedBaseMessage {
  id: string;
  type: string;
  createdAt: string;
}

export type ReadAdvanceDecision = 'advance' | 'same' | 'behind' | 'unknown';

function parsedTime(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function compareBaseMessages(left: OrderedBaseMessage, right: OrderedBaseMessage): number {
  const time = parsedTime(left.createdAt) - parsedTime(right.createdAt);
  return time || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
}

export function readAdvanceDecision(
  currentMessageId: string | null,
  candidateMessageId: string,
  loadedMessages: OrderedBaseMessage[],
): ReadAdvanceDecision {
  if (!currentMessageId) return 'advance';
  if (currentMessageId === candidateMessageId) return 'same';
  const byId = new Map(loadedMessages.map((message) => [message.id, message]));
  const current = byId.get(currentMessageId);
  const candidate = byId.get(candidateMessageId);
  if (!current || !candidate) return 'unknown';
  return compareBaseMessages(candidate, current) > 0 ? 'advance' : 'behind';
}

/** Latest logical message that can serve as a read position. */
export function latestReadableMessageId(messages: OrderedBaseMessage[]): string | null {
  const readable = messages
    .filter((message) => message.type === 'message' || message.type === 'edit')
    .sort(compareBaseMessages);
  return readable.length > 0 ? readable[readable.length - 1].id : null;
}

export function defaultChannelReadState(channelId: string): ChannelReadState {
  return {
    channelId,
    favorite: false,
    muted: false,
    hidden: false,
    notificationLevel: 'all',
    updatedAt: null,
    lastReadMessageId: null,
    latestMessageId: null,
    unreadCount: 0,
  };
}

export function mergeChannelPreference(
  current: ChannelReadState | undefined,
  preference: ChannelPreference,
): ChannelReadState {
  return {
    ...(current || defaultChannelReadState(preference.channelId)),
    ...preference,
  };
}

export interface MentionCandidateMessage extends OrderedBaseMessage {
  authorId: string;
  content: string;
  broadcastMention?: boolean | null;
}

export interface LoadedMentionScan {
  count: number;
  scannedMessages: number;
  boundaryKnown: boolean;
  completeForUnreadWindow: boolean;
}

const NON_CONTENT_MARKERS = new Set([
  UNAVAILABLE_MESSAGE_MARKER,
  UNVERIFIED_MESSAGE_MARKER,
  TAMPERED_MESSAGE_MARKER,
]);

function containsLocalMention(content: string, userId: string, displayName: string): boolean {
  return messageMentionsCurrentUser(content, [{ userId, displayName }], userId, false);
}

function containsAuthenticatedBroadcastMention(message: MentionCandidateMessage): boolean {
  if (message.broadcastMention !== true) return false;
  return /(^|[^\p{L}\p{N}_])@(everyone|here)(?=$|[^\p{L}\p{N}_])/iu
    .test(message.content.normalize('NFKC'));
}

/**
 * Count only mentions whose plaintext and unread boundary are both available
 * on this device. This deliberately does not claim server-wide precision.
 */
export function scanLoadedMentionUnread(
  messages: MentionCandidateMessage[],
  user: { id: string; displayName: string },
  lastReadMessageId: string | null,
  hasMoreHistory: boolean,
): LoadedMentionScan {
  const baseMessages = messages
    .filter((message) => message.type === 'message' || message.type === 'edit' || message.type === 'delete')
    .sort(compareBaseMessages);
  const boundaryIndex = lastReadMessageId
    ? baseMessages.findIndex((message) => message.id === lastReadMessageId)
    : -1;
  const boundaryKnown = lastReadMessageId === null || boundaryIndex >= 0;
  if (!boundaryKnown) {
    return { count: 0, scannedMessages: baseMessages.length, boundaryKnown: false, completeForUnreadWindow: false };
  }
  const unread = baseMessages.slice(boundaryIndex + 1);
  const count = unread.filter((message) => (
    message.type !== 'delete'
    && message.authorId !== user.id
    && Boolean(message.content)
    && !NON_CONTENT_MARKERS.has(message.content)
    && (
      containsLocalMention(message.content, user.id, user.displayName)
      || containsAuthenticatedBroadcastMention(message)
    )
  )).length;
  return {
    count,
    scannedMessages: unread.length,
    boundaryKnown: true,
    completeForUnreadWindow: lastReadMessageId !== null || !hasMoreHistory,
  };
}

export function sortBookmarks(bookmarks: MessageBookmark[]): MessageBookmark[] {
  return [...bookmarks].sort((left, right) => (
    right.createdAt.localeCompare(left.createdAt)
    || (left.messageId < right.messageId ? 1 : left.messageId > right.messageId ? -1 : 0)
  ));
}
