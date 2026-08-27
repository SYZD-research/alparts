import type { Message } from '@alparts/shared';
import { compareMessageEvents } from './message-projector';

export function loadedThreadReplies(messages: Message[], rootMessageId: string): Message[] {
  return messages
    .filter((message) => message.refMessageId === rootMessageId)
    .sort(compareMessageEvents);
}

export function countLoadedThreadReplies(messages: Message[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const message of messages) {
    if (!message.refMessageId) continue;
    counts[message.refMessageId] = (counts[message.refMessageId] || 0) + 1;
  }
  return counts;
}
