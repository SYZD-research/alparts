import { serializeMessageEnvelope, type Attachment, type Message, type Reaction } from '@alparts/shared';

export type ProjectedMessage = Message & {
  editedAt?: string;
  deletedByUserId?: string;
  deletedByDisplayName?: string;
};

const localVerificationState = Symbol('alparts.message.local-verification-state');
const authenticatedEnvelopeConflict = Symbol('alparts.message.authenticated-envelope-conflict');
const channelKeyUnavailable = Symbol('alparts.message.channel-key-unavailable');

type LocallyVerifiedEvent = Message & {
  [localVerificationState]?: boolean;
  [authenticatedEnvelopeConflict]?: true;
  [channelKeyUnavailable]?: true;
};

/** Network JSON cannot manufacture this process-local Symbol marker. */
export function markMessageCryptoVerification(message: Message, verified: boolean): Message {
  const { [channelKeyUnavailable]: _unavailable, ...retryable } = withoutLegacyVerificationProperty(message) as LocallyVerifiedEvent;
  return { ...retryable, [localVerificationState]: verified } as Message;
}

export function markMessageKeyUnavailable(message: Message): Message {
  return {
    ...withoutLegacyVerificationProperty(message),
    content: '',
    [localVerificationState]: false,
    [channelKeyUnavailable]: true,
  } as Message;
}

export function isMessageKeyUnavailable(message: Message): boolean {
  return (message as LocallyVerifiedEvent)[channelKeyUnavailable] === true;
}

export function retryMessageKeyVerification(message: Message): Message {
  const {
    [localVerificationState]: _verification,
    [channelKeyUnavailable]: _unavailable,
    ...retryable
  } = withoutLegacyVerificationProperty(message) as LocallyVerifiedEvent;
  return retryable as Message;
}

export function getMessageCryptoVerificationState(message: Message): boolean | undefined {
  return (message as LocallyVerifiedEvent)[localVerificationState];
}

export function hasAuthenticatedEnvelopeConflict(message: Message): boolean {
  return (message as LocallyVerifiedEvent)[authenticatedEnvelopeConflict] === true;
}

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
  const currentEvent = withoutLegacyVerificationProperty(current);
  const incomingEvent = withoutLegacyVerificationProperty(incoming);
  if (isAuthenticatedMessageEvent(currentEvent) || isAuthenticatedMessageEvent(incomingEvent)) {
    const currentEnvelope = authenticatedEnvelope(currentEvent);
    const incomingEnvelope = authenticatedEnvelope(incomingEvent);
    if (
      hasAuthenticatedEnvelopeConflict(currentEvent)
      || hasAuthenticatedEnvelopeConflict(incomingEvent)
      || currentEnvelope === null
      || incomingEnvelope === null
      || currentEnvelope !== incomingEnvelope
    ) {
      // One immutable event id must never identify two signed envelopes. Keep
      // the first projection stable, discard all plaintext, and make the
      // equivocation sticky until the channel is explicitly reloaded.
      return {
        ...currentEvent,
        content: '',
        [localVerificationState]: false,
        [authenticatedEnvelopeConflict]: true,
      } as Message;
    }

    const currentVerification = getMessageCryptoVerificationState(currentEvent);
    const incomingVerification = getMessageCryptoVerificationState(incomingEvent);
    const verified = currentVerification === true || incomingVerification === true
      ? true
      : currentVerification === false || incomingVerification === false
        ? false
        : undefined;
    const trustedContent = incomingVerification === true
      ? incomingEvent.content
      : currentVerification === true
        ? currentEvent.content
        : '';
    const trustedAuthor = incomingVerification === true
      ? incomingEvent.author
      : currentVerification === true
        ? currentEvent.author
        : incomingEvent.author || currentEvent.author;
    const merged = {
      ...currentEvent,
      ...incomingEvent,
      // Plaintext and the verified author binding are local results. A wire
      // duplicate may update server-owned aggregates, but can never provide or
      // replace either value merely by copying the signed ciphertext.
      content: trustedContent,
      author: trustedAuthor,
      reactions: incomingEvent.reactions || currentEvent.reactions,
      attachments: mergeAttachments(currentEvent.attachments, incomingEvent.attachments),
      isPinned: incomingEvent.isPinned,
    } as LocallyVerifiedEvent;
    if (verified !== undefined) merged[localVerificationState] = verified;
    return merged;
  }

  return {
    ...currentEvent,
    ...incomingEvent,
    content: incomingEvent.content || currentEvent.content,
    author: incomingEvent.author || currentEvent.author,
    reactions: incomingEvent.reactions || currentEvent.reactions,
    attachments: mergeAttachments(currentEvent.attachments, incomingEvent.attachments),
    isPinned: incomingEvent.isPinned,
  };
}

function isAuthenticatedMessageEvent(message: Message): boolean {
  return message.type === 'message' || message.type === 'edit' || message.type === 'delete';
}

function authenticatedEnvelope(message: Message): string | null {
  if (!isAuthenticatedMessageEvent(message) || !message.deviceId || !message.signature) return null;
  return `${serializeMessageEnvelope({
    type: message.type as 'message' | 'edit' | 'delete',
    channelId: message.channelId,
    authorId: message.authorId,
    deviceId: message.deviceId,
    keyVersion: message.keyVersion,
    idempotencyKey: message.idempotencyKey,
    refMessageId: message.refMessageId,
    broadcastMention: message.broadcastMention,
    encryptedContent: message.encryptedContent,
    contentNonce: message.contentNonce,
  })}\u0000${message.postId ?? ''}\u0000${message.signature}`;
}

function withoutLegacyVerificationProperty(message: Message): Message {
  // The former string property was forgeable by JSON returned by the server.
  // Strip it at every merge boundary while retaining process-local Symbols.
  const { cryptoVerified: _untrusted, ...safe } = message as Message & { cryptoVerified?: unknown };
  return safe as Message;
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
const canonicalBatches = new WeakSet<Message[]>();
export function mergeMessageEvents(...batches: Message[][]): Message[] {
  if (batches.length === 1 && canonicalBatches.has(batches[0])) return batches[0];
  const events = new Map<string, Message>();
  for (const batch of batches) {
    const canonical = canonicalBatches.has(batch);
    for (const event of batch) {
      const existing = events.get(event.id);
      events.set(event.id, existing ? mergeDuplicateEvent(existing, event) : canonical ? event : withoutLegacyVerificationProperty(event));
    }
  }
  const ordered = quarantineReplayedEvents([...events.values()].sort(compareMessageEvents));
  canonicalBatches.add(ordered);
  return ordered;
}

/**
 * The server keeps one event per channel and idempotency key, so a second
 * signed event carrying the same author and key under another id replays an
 * earlier operation, such as an old edit that would roll a message back.
 * Only the first verified one counts; later ones are quarantined like an
 * equivocation.
 */
function quarantineReplayedEvents(ordered: Message[]): Message[] {
  const seen = new Set<string>();
  let changed = false;
  const result = ordered.map((event) => {
    if (!isAuthenticatedMessageEvent(event) || !event.idempotencyKey) return event;
    const conflicted = hasAuthenticatedEnvelopeConflict(event);
    if (!conflicted && getMessageCryptoVerificationState(event) !== true) return event;
    const key = `${event.channelId}\u0000${event.authorId}\u0000${event.idempotencyKey}`;
    const replay = seen.has(key);
    seen.add(key);
    if (!replay || conflicted) return event;
    changed = true;
    return {
      ...event,
      content: '',
      [localVerificationState]: false,
      [authenticatedEnvelopeConflict]: true,
    } as Message;
  });
  return changed ? result : ordered;
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
  return projectOrderedMessageEvents(mergeMessageEvents(rawEvents));
}

/** Internal projection of an already deduplicated, ordered event window. */
export function projectOrderedMessageEvents(orderedEvents: Message[]): ProjectedMessage[] {
  const projected = new Map<string, ProjectedMessage>();

  for (const event of orderedEvents) {
    if (event.type === 'message' || event.type === 'system') {
      projected.set(event.id, {
        ...event,
        // Network payloads never get to supply display plaintext. A base
        // message becomes visible only after its signature and AEAD verify.
        content: event.type === 'message' && getMessageCryptoVerificationState(event) !== true
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
      if (getMessageCryptoVerificationState(event) !== true) continue;
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
      if (getMessageCryptoVerificationState(event) !== true) continue;
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

  // Replacing an edit/delete preserves the insertion position of its base.
  return [...projected.values()];
}
