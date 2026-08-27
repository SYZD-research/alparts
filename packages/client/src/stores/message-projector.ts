import type { Attachment, Message, Reaction } from '@alparts/shared';

export type ProjectedMessage = Message & {
  editedAt?: string;
  deletedByUserId?: string;
  deletedByDisplayName?: string;
};

type LocallyVerifiedEvent = Message & { cryptoVerified?: boolean };

function eventTime(event: Message): number {
  const value = Date.parse(event.createdAt);
  return Number.isFinite(value) ? value : 0;
}

export function compareMessageEvents(left: Message, right: Message): number {
  const timeDifference = eventTime(left) - eventTime(right);
  return timeDifference || compareBinaryIds(left.id, right.id);
}

/** PostgreSQL UUID ordering is byte-wise; UUID text has fixed separators. */
export function compareBinaryIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function mergeDuplicateEvent(current: Message, incoming: Message): Message {
  const sameCiphertext = current.encryptedContent === incoming.encryptedContent
    && current.contentNonce === incoming.contentNonce
    && current.signature === incoming.signature;
  return {
    ...current,
    ...incoming,
    // Preserve a locally decrypted body only for the exact same authenticated
    // envelope. Pin/reaction aggregates are authoritative snapshots and may
    // legitimately become empty/false, so they must not be OR-merged.
    content: incoming.content || (sameCiphertext ? current.content : ''),
    author: incoming.author || current.author,
    reactions: incoming.reactions || current.reactions,
    attachments: mergeAttachments(current.attachments, incoming.attachments),
    isPinned: incoming.isPinned,
  };
}

function mergeAttachments(current: Attachment[] | undefined, incoming: Attachment[] | undefined): Attachment[] | undefined {
  if (current === undefined && incoming === undefined) return undefined;
  const byId = new Map<string, Attachment>();
  for (const attachment of [...(current || []), ...(incoming || [])]) byId.set(attachment.id, attachment);
  return [...byId.values()].sort((left, right) => (
    left.createdAt < right.createdAt ? -1 : left.createdAt > right.createdAt ? 1 : compareBinaryIds(left.id, right.id)
  ));
}

/** Merge at-least-once event batches by immutable event id. */
export function mergeMessageEvents(...batches: Message[][]): Message[] {
  const events = new Map<string, Message>();
  for (const event of batches.flat()) {
    const existing = events.get(event.id);
    events.set(event.id, existing ? mergeDuplicateEvent(existing, event) : event);
  }
  return [...events.values()].sort(compareMessageEvents);
}

function addReaction(reactions: Reaction[], emoji: string, userId: string): Reaction[] {
  const existing = reactions.find((reaction) => reaction.emoji === emoji);
  if (!existing) return [...reactions, { emoji, count: 1, userIds: [userId] }];
  if (existing.userIds.includes(userId)) return reactions;
  return reactions.map((reaction) => reaction.emoji === emoji
    ? { ...reaction, count: reaction.userIds.length + 1, userIds: [...reaction.userIds, userId] }
    : reaction);
}

/** Fold immutable wire events into the logical messages rendered by the UI. */
export function projectMessageEvents(rawEvents: Message[]): ProjectedMessage[] {
  const orderedEvents = mergeMessageEvents(rawEvents);
  const projected = new Map<string, ProjectedMessage>();

  for (const event of orderedEvents) {
    if (event.type === 'message' || event.type === 'system') {
      projected.set(event.id, {
        ...event,
        // Network payloads never get to supply display plaintext. A base
        // message becomes visible only after its signature and AEAD verify.
        content: event.type === 'message' && (event as LocallyVerifiedEvent).cryptoVerified !== true
          ? ''
          : event.content,
        reactions: [...(event.reactions || [])],
      });
      continue;
    }

    const targetId = event.refMessageId;
    if (!targetId) continue;
    const target = projected.get(targetId);
    if (!target) continue;

    if (event.type === 'edit') {
      if ((event as LocallyVerifiedEvent).cryptoVerified !== true) continue;
      if (target.type === 'delete' || event.authorId !== target.authorId) continue;
      projected.set(targetId, {
        ...target,
        type: 'edit',
        content: event.content,
        encryptedContent: event.encryptedContent,
        contentNonce: event.contentNonce,
        deviceId: event.deviceId,
        keyVersion: event.keyVersion,
        signature: event.signature,
        broadcastMention: event.broadcastMention ?? false,
        idempotencyKey: event.idempotencyKey,
        editedAt: event.createdAt,
        refMessageId: target.refMessageId,
      });
      continue;
    }

    if (event.type === 'delete') {
      if ((event as LocallyVerifiedEvent).cryptoVerified !== true) continue;
      projected.set(targetId, {
        ...target,
        type: 'delete',
        content: '',
        deletedByUserId: event.authorId,
        deletedByDisplayName: event.author?.displayName,
      });
      continue;
    }

    if (event.type === 'reaction') {
      const emoji = event.content || event.encryptedContent;
      if (!emoji) continue;
      projected.set(targetId, {
        ...target,
        reactions: addReaction(target.reactions || [], emoji, event.authorId),
      });
    }
  }

  return [...projected.values()].sort(compareMessageEvents);
}
