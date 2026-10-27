import {
  serializeMessageEnvelope,
  type Attachment,
  type Message,
  type SignedEventReference,
} from '@alparts/shared';

export type ProjectedMessage = Message & {
  editedAt?: string;
  deletedByUserId?: string;
  deletedByDisplayName?: string;
  /** The idempotency key the message was sent with (an edit replaces idempotencyKey). */
  originIdempotencyKey?: string;
  /**
   * What the client can tell about the events around this message (v6):
   * 'missing' when events written before it were not delivered, 'order'
   * when it is not where its author's device saw it.
   */
  sequenceNotice?: SequenceNotice;
  /** A later edit of this message was delivered but cannot be shown in order (v6). */
  editUncertain?: true;
};

/** See ProjectedMessage.sequenceNotice. */
export type SequenceNotice = 'missing' | 'order';

const localVerificationState = Symbol('alparts.message.local-verification-state');
/** The v5 signature verified: refBinding and postBinding are what the author signed. */
const boundReferences = Symbol('alparts.message.bound-references');
/**
 * The v6 signature verified: deviceSeq, seenHeads and supersedes are what
 * the author's device signed. Set even when the text cannot be read (no key)
 * or did not decrypt, since the signature covers the ciphertext as sent.
 */
const sequencedEnvelope = Symbol('alparts.message.sequenced-envelope');
const authenticatedEnvelopeConflict = Symbol('alparts.message.authenticated-envelope-conflict');
const channelKeyUnavailable = Symbol('alparts.message.channel-key-unavailable');

type LocallyVerifiedEvent = Message & {
  [localVerificationState]?: boolean;
  [boundReferences]?: true;
  [sequencedEnvelope]?: true;
  [authenticatedEnvelopeConflict]?: true;
  [channelKeyUnavailable]?: true;
};

/**
 * Network JSON cannot manufacture these process-local Symbol markers. `bound`
 * records that the v5 (or v6) signature verified, so the event's refBinding
 * and postBinding are what its author signed. `sequenced` records that the
 * v6 signature verified, which holds for an event whose text did not decrypt.
 */
export function markMessageCryptoVerification(message: Message, verified: boolean, bound = false, sequenced = false): Message {
  const {
    [channelKeyUnavailable]: _unavailable,
    [boundReferences]: _bound,
    [sequencedEnvelope]: _sequenced,
    ...retryable
  } = withoutLegacyVerificationProperty(message) as LocallyVerifiedEvent;
  return {
    ...retryable,
    [localVerificationState]: verified,
    ...(verified && bound ? { [boundReferences]: true } : {}),
    ...(sequenced ? { [sequencedEnvelope]: true } : {}),
  } as Message;
}

/** Whether the event's v6 signature verified: its number, heads and replaced version are its author's. */
export function hasSequencedEnvelope(message: Message): boolean {
  return (message as LocallyVerifiedEvent)[sequencedEnvelope] === true;
}

/** Whether the event was verified as v5: its references name events as their authors signed them. */
export function hasBoundReferences(message: Message): boolean {
  return (message as LocallyVerifiedEvent)[boundReferences] === true
    && (message as LocallyVerifiedEvent)[localVerificationState] === true;
}

/** Whether `target` is the event `reference` names: same author, same signed idempotency key. */
export function isReferencedEvent(
  target: Pick<ProjectedMessage, 'authorId' | 'idempotencyKey' | 'originIdempotencyKey'>,
  reference: SignedEventReference | null | undefined,
): boolean {
  return Boolean(reference)
    && target.authorId === reference!.authorId
    && (target.originIdempotencyKey ?? target.idempotencyKey) === reference!.idempotencyKey;
}

/**
 * Whether an event may apply to, or be shown with, the message under the id
 * it names. A v5 event must name that very message; an older event can only
 * name an id, so any message under it is taken (documented limit).
 */
function namesEvent(
  event: Message,
  target: Pick<ProjectedMessage, 'authorId' | 'idempotencyKey' | 'originIdempotencyKey'>,
  reference: SignedEventReference | null | undefined,
): boolean {
  return !hasBoundReferences(event) || isReferencedEvent(target, reference);
}

/**
 * The message a quote shows: undefined while the message under its id is not
 * loaded, null when the quote cannot be trusted: the message carrying it did
 * not verify, so its refMessageId is whatever the server served, or the
 * message under that id is not the one quoted.
 */
export function quotedMessage(message: Message, messages: readonly ProjectedMessage[]): ProjectedMessage | null | undefined {
  if (!message.refMessageId) return undefined;
  if (getMessageCryptoVerificationState(message) !== true) return null;
  const target = messages.find((candidate) => candidate.id === message.refMessageId);
  if (!target) return undefined;
  return namesEvent(message, target, message.refBinding) ? target : null;
}

/**
 * Whether a forum message belongs under this post's first message. Only a
 * message that verified names its post: otherwise postId is the server's.
 */
export function belongsToPost(message: Message, root: ProjectedMessage): boolean {
  return getMessageCryptoVerificationState(message) === true
    && message.postId === root.id
    && namesEvent(message, root, message.postBinding);
}

/** The event cannot be read on this device; `sequenced` keeps that its v6 signature verified. */
export function markMessageKeyUnavailable(message: Message, sequenced = false): Message {
  const { [sequencedEnvelope]: _sequenced, ...rest } = withoutLegacyVerificationProperty(message) as LocallyVerifiedEvent;
  return {
    ...rest,
    content: '',
    [localVerificationState]: false,
    [channelKeyUnavailable]: true,
    ...(sequenced ? { [sequencedEnvelope]: true } : {}),
  } as Message;
}

export function isMessageKeyUnavailable(message: Message): boolean {
  return (message as LocallyVerifiedEvent)[channelKeyUnavailable] === true;
}

export function retryMessageKeyVerification(message: Message): Message {
  const {
    [localVerificationState]: _verification,
    [channelKeyUnavailable]: _unavailable,
    [sequencedEnvelope]: _sequenced,
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
  const bound = (currentVerification === true && hasBoundReferences(currentEvent))
    || (incomingVerification === true && hasBoundReferences(incomingEvent));
  // Both copies carry the same signed envelope, so a v6 signature that
  // verified on one verified for the other.
  const sequenced = hasSequencedEnvelope(currentEvent) || hasSequencedEnvelope(incomingEvent);
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
    // The server time of an event never changes. A copy with another time
    // must not move an event already held, which would let a server put an
    // old edit back on top.
    createdAt: currentEvent.createdAt,
    reactions: incomingEvent.reactions || currentEvent.reactions,
    attachments: mergeAttachments(currentEvent.attachments, incomingEvent.attachments),
    isPinned: incomingEvent.isPinned,
  } as LocallyVerifiedEvent;
  if (verified !== undefined) merged[localVerificationState] = verified;
  if (bound) merged[boundReferences] = true;
  else delete merged[boundReferences];
  if (sequenced) merged[sequencedEnvelope] = true;
  else delete merged[sequencedEnvelope];
  return merged;
}

/**
 * Whether the event is of a type its author signs. The server stores nothing
 * else, so any other type in a response or a socket event was made up.
 */
export function isAuthenticatedMessageEvent(message: { type: string }): boolean {
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
  })}\u0000${message.postId ?? ''}\u0000${JSON.stringify([
    message.refBinding ?? null,
    message.postBinding ?? null,
    message.deviceSeq ?? null,
    message.seenHeads ?? null,
    message.supersedes ?? null,
  ])}\u0000${message.signature}`;
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
      if (!isAuthenticatedMessageEvent(event)) continue;
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

/**
 * What the projector may assume about the window it is given:
 * `contiguous` when the events are every event of the channel from the
 * oldest one held up to the newest (so a device's events between two held
 * ones are held too); `complete` when the window also starts at the
 * channel's first event. A forum window holds posts loaded one by one, so it
 * is neither.
 */
export interface EventWindow {
  contiguous: boolean;
  complete: boolean;
}

const UNKNOWN_WINDOW: EventWindow = { contiguous: false, complete: false };

/** Fold immutable wire events into the logical messages rendered by the UI. */
export function projectMessageEvents(rawEvents: Message[], window: EventWindow = UNKNOWN_WINDOW): ProjectedMessage[] {
  return projectOrderedMessageEvents(mergeMessageEvents(rawEvents), window);
}

/** The number an event claims, if it is a valid one (signed only once hasSequencedEnvelope holds). */
function claimedSequence(event: Message): number | null {
  const value = event.deviceSeq;
  return event.deviceId && Number.isSafeInteger(value) && (value as number) >= 1 ? value as number : null;
}

/**
 * Check an ordered window against what v6 events signed (formal model M10).
 * Returns, per event id, 'missing' when an event written before it is not in
 * the window although it should be, or 'order' when the server put it where
 * its author's device could not have written it:
 *
 * - A device numbers its events 1, 2, 3, … with no gaps. In a contiguous
 *   window, a device's held events must have consecutive numbers ('missing'
 *   otherwise); in a complete one its first must be 1. An unverified message
 *   still fills its number (it is shown as one that could not be verified),
 *   and so does an edit or a deletion whose check has not finished.
 * - The verified events of one device must appear in increasing number
 *   ('order' otherwise). The server takes no event in an older layout once
 *   it takes v6 ones, and gives each new event a later time than every
 *   event before it, so a verified event in an older layout after a
 *   verified v6 one was moved there ('order').
 * - Each event a v6 event names in seenHeads comes before it, and so does
 *   every event of that device with a lower number ('order' otherwise), under
 *   the same signed key ('order' otherwise: the server showed different
 *   events under one number). If it is not held but must be in a contiguous
 *   window, it is 'missing'.
 */
export function analyzeEventOrder(ordered: readonly Message[], window: EventWindow): Map<string, SequenceNotice> {
  const notices = new Map<string, SequenceNotice>();
  const note = (event: Message, notice: SequenceNotice) => {
    if (notices.get(event.id) !== 'missing') notices.set(event.id, notice);
  };
  const positions = new Map<string, { index: number; idempotencyKey: string }>();
  const lowestClaimed = new Map<string, number>();
  // Per device, the verified numbers held, with the last place each number up
  // to it is held at: whatever a head names, all of these must come before.
  const verifiedByDevice = new Map<string, Array<{ seq: number; index: number }>>();
  ordered.forEach((event, index) => {
    const seq = claimedSequence(event);
    if (seq === null) return;
    const lowest = lowestClaimed.get(event.deviceId!);
    if (lowest === undefined || seq < lowest) lowestClaimed.set(event.deviceId!, seq);
    if (!hasSequencedEnvelope(event)) return;
    const key = `${event.deviceId}\u0000${seq}`;
    if (!positions.has(key)) positions.set(key, { index, idempotencyKey: event.idempotencyKey });
    verifiedByDevice.set(event.deviceId!, [...(verifiedByDevice.get(event.deviceId!) ?? []), { seq, index }]);
  });
  /** Whether an event of this device numbered up to `seq` is held after `index`. */
  const heldAfter = (deviceId: string, seq: number, index: number) => (verifiedByDevice.get(deviceId) ?? [])
    .some((held) => held.seq <= seq && held.index > index);

  const lastClaimed = new Map<string, number>();
  const lastVerified = new Map<string, number>();
  let sequencedSeen = false;
  ordered.forEach((event, index) => {
    const seq = claimedSequence(event);
    const verified = getMessageCryptoVerificationState(event) === true;
    const sequenced = hasSequencedEnvelope(event);
    // A message fills its number even unverified (it is shown as such); an
    // edit or a deletion fills it while its check is pending or once it passed.
    if (seq !== null && (sequenced || event.type === 'message' || getMessageCryptoVerificationState(event) === undefined)) {
      const device = event.deviceId!;
      const previous = lastClaimed.get(device);
      if (window.contiguous && (previous === undefined ? window.complete && seq > 1 : seq > previous + 1)) note(event, 'missing');
      if (previous === undefined || seq > previous) lastClaimed.set(device, seq);
    }
    if (sequenced) {
      const device = event.deviceId!;
      const previous = lastVerified.get(device);
      if (previous !== undefined && seq! <= previous) note(event, 'order');
      else lastVerified.set(device, seq!);
      sequencedSeen = true;
      for (const head of event.seenHeads ?? []) {
        if (heldAfter(head.deviceId, head.deviceSeq, index)) note(event, 'order');
        const seen = positions.get(`${head.deviceId}\u0000${head.deviceSeq}`);
        if (seen) {
          if (seen.idempotencyKey !== head.idempotencyKey) note(event, 'order');
          continue;
        }
        // Not held: it should be when the window reaches back past it.
        const lowest = lowestClaimed.get(head.deviceId);
        if (window.contiguous && (window.complete || (lowest !== undefined && lowest < head.deviceSeq))) note(event, 'missing');
      }
    } else if (verified && sequencedSeen) {
      note(event, 'order');
    }
  });
  return notices;
}

/** Internal projection of an already deduplicated, ordered event window. */
export function projectOrderedMessageEvents(orderedEvents: Message[], window: EventWindow = UNKNOWN_WINDOW): ProjectedMessage[] {
  return projectMessageWindow(orderedEvents, window).messages;
}

/**
 * The messages of a window, and what the client noticed that no shown message
 * can carry: events missing or out of order around an edit or a deletion of a
 * message that is not shown (formal model M10, MO-drop and MO-order).
 */
export interface ProjectedWindow {
  messages: ProjectedMessage[];
  channelNotice: SequenceNotice | null;
}

export function projectMessageWindow(orderedEvents: Message[], window: EventWindow = UNKNOWN_WINDOW): ProjectedWindow {
  const projected = new Map<string, ProjectedMessage>();
  let channelNotice: SequenceNotice | null = null;
  const noteChannel = (notice: SequenceNotice) => {
    if (channelNotice !== 'missing') channelNotice = notice;
  };
  const notices = analyzeEventOrder(orderedEvents, window);
  // v6 edits wait here until the version they replace is the one shown.
  const waitingEdits = new Map<string, Message[]>();
  let missingCarried = false;
  let lastBaseId: string | null = null;

  const applyEdit = (event: Message, target: ProjectedMessage): ProjectedMessage => {
    const edited: ProjectedMessage = {
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
    };
    projected.set(target.id, edited);
    return edited;
  };
  // Whether an edit may change the message shown: the author's verified
  // edit of a verified message, signed (in v5 or v6) for that very message.
  const mayEdit = (event: Message, target: ProjectedMessage) => getMessageCryptoVerificationState(event) === true
    && target.type !== 'delete'
    && event.authorId === target.authorId
    // The edited message keeps its base's references, which are the
    // author's only if the base verified.
    && getMessageCryptoVerificationState(target) === true
    // A v5 edit applies only to the message it was signed for.
    && namesEvent(event, target, event.refBinding);
  // Apply the waiting v6 edits that now replace the shown version, in turn.
  const applyWaitingEdits = (targetId: string) => {
    for (;;) {
      const target = projected.get(targetId);
      const waiting = waitingEdits.get(targetId);
      if (!target || target.type === 'delete' || !waiting?.length) return;
      const next = waiting.findIndex((edit) => edit.supersedes === target.idempotencyKey && mayEdit(edit, target));
      if (next < 0) return;
      const [edit] = waiting.splice(next, 1);
      applyEdit(edit, target);
    }
  };

  for (const event of orderedEvents) {
    // A window handed in directly is held to the store's rule: only signed events.
    if (!isAuthenticatedMessageEvent(event)) continue;
    const notice = notices.get(event.id);
    if (event.type === 'message') {
      projected.set(event.id, {
        ...event,
        // Network payloads never get to supply display plaintext. A base
        // message becomes visible only after its signature and AEAD verify.
        content: getMessageCryptoVerificationState(event) !== true ? '' : event.content,
        reactions: [...(event.reactions || [])],
        originIdempotencyKey: event.idempotencyKey,
        ...(notice === 'missing' || missingCarried ? { sequenceNotice: 'missing' as const } : notice ? { sequenceNotice: notice } : {}),
      });
      missingCarried = false;
      lastBaseId = event.id;
      // A v6 edit served before its message applies once the message is here.
      applyWaitingEdits(event.id);
      continue;
    }
    // What is missing before an edit or a deletion is shown on the next message.
    if (notice === 'missing') missingCarried = true;

    const targetId = event.refMessageId;
    if (!targetId) continue;
    // A v6 edit replaces one version: it waits until that one is shown,
    // even if the server served it before its message.
    if (event.type === 'edit' && hasSequencedEnvelope(event) && getMessageCryptoVerificationState(event) === true) {
      waitingEdits.set(targetId, [...(waitingEdits.get(targetId) ?? []), event]);
    }
    const target = projected.get(targetId);
    if (!target) {
      if (notice === 'order') noteChannel('order');
      continue;
    }
    if (notice === 'order' && !target.sequenceNotice) projected.set(targetId, { ...target, sequenceNotice: 'order' });

    if (event.type === 'edit') {
      const current = projected.get(targetId)!;
      if (hasSequencedEnvelope(event)) {
        applyWaitingEdits(targetId);
        continue;
      }
      if (!mayEdit(event, current)) continue;
      applyEdit(event, current);
      applyWaitingEdits(targetId);
      continue;
    }

    if (event.type === 'delete') {
      if (getMessageCryptoVerificationState(event) !== true) continue;
      if (!namesEvent(event, target, event.refBinding)) continue;
      const current = projected.get(targetId)!;
      projected.set(targetId, {
        ...current,
        type: 'delete',
        content: '',
        deletedByUserId: event.authorId,
        deletedByDisplayName: event.author?.displayName,
      });
    }
  }
  if (missingCarried) {
    if (lastBaseId) {
      const last = projected.get(lastBaseId)!;
      projected.set(lastBaseId, { ...last, sequenceNotice: 'missing' });
    } else {
      noteChannel('missing');
    }
  }
  // A v6 edit of a message shown that never replaced the shown version: the
  // version it replaces was not delivered, or another edit already replaced it.
  for (const [targetId, waiting] of waitingEdits) {
    const target = projected.get(targetId);
    if (target && target.type !== 'delete' && waiting.some((edit) => mayEdit(edit, target))) {
      projected.set(targetId, { ...target, editUncertain: true });
    }
  }

  // Replacing an edit/delete preserves the insertion position of its base.
  return { messages: [...projected.values()], channelNotice };
}
