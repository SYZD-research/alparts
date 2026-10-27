import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Message, User } from '@alparts/shared';
import {
  analyzeEventOrder,
  hasSequencedEnvelope,
  markMessageCryptoVerification,
  markMessageKeyUnavailable,
  mergeMessageEvents,
  projectOrderedMessageEvents,
  type EventWindow,
} from './message-projector';
import { nextDeviceSequence, noteExpectedSequence, noteStoredSequence, resetDeviceSequences, seenHeadsOf } from './device-sequence';

const author: User = {
  id: 'user-1',
  email: 'alice@example.test',
  displayName: 'Alice',
  avatarUrl: null,
  status: 'online',
  createdAt: '2026-01-01T00:00:00.000Z',
};

let clock = 0;

/** A v6 event whose signature verified (unless `verified` says otherwise). */
function sequenced(
  id: string,
  deviceId: string,
  deviceSeq: number,
  fields: Partial<Message> = {},
  verified: boolean | 'pending' = true,
): Message {
  clock += 1;
  const base = {
    id,
    channelId: 'channel-1',
    authorId: fields.authorId ?? author.id,
    author,
    deviceId,
    content: fields.content ?? `text ${id}`,
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type: 'message',
    refMessageId: null,
    refBinding: null,
    reactions: [],
    isPinned: false,
    idempotencyKey: `key-${id}`,
    createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, clock)).toISOString(),
    deviceSeq,
    seenHeads: [],
    supersedes: null,
    ...fields,
  } as Message;
  if (verified === 'pending') return base;
  return markMessageCryptoVerification(base, verified, true, verified);
}

const CONTIGUOUS: EventWindow = { contiguous: true, complete: false };
const COMPLETE: EventWindow = { contiguous: true, complete: true };
const FORUM: EventWindow = { contiguous: false, complete: false };

const notices = (events: Message[], window: EventWindow) => Object.fromEntries(analyzeEventOrder(events, window));

afterEach(() => {
  resetDeviceSequences();
  vi.unstubAllGlobals();
});

/** The base message as a v6 edit names it. */
const editOf = (id: string) => ({ refMessageId: id, refBinding: { authorId: author.id, idempotencyKey: `key-${id}` } });

describe('what a client can tell from v6 events (formal model M10)', () => {
  it('accepts every honest order: consecutive numbers, heads before the events that saw them', () => {
    const a1 = sequenced('a1', 'A', 1);
    const b1 = sequenced('b1', 'B', 1, { seenHeads: [{ deviceId: 'A', deviceSeq: 1, idempotencyKey: 'key-a1' }] });
    const a2 = sequenced('a2', 'A', 2, { seenHeads: [{ deviceId: 'B', deviceSeq: 1, idempotencyKey: 'key-b1' }] });
    expect(notices([a1, b1, a2], COMPLETE)).toEqual({});
    expect(notices([a1, b1, a2], CONTIGUOUS)).toEqual({});
  });

  it('notices an event a device wrote between two delivered ones', () => {
    const a1 = sequenced('a1', 'A', 1);
    const a3 = sequenced('a3', 'A', 3);
    expect(notices([a1, a3], CONTIGUOUS)).toEqual({ a3: 'missing' });
    // A forum window holds posts loaded one by one: there a gap means nothing.
    expect(notices([a1, a3], FORUM)).toEqual({});
  });

  it('notices the first events of a device missing from a complete window only', () => {
    const a2 = sequenced('a2', 'A', 2);
    expect(notices([a2], COMPLETE)).toEqual({ a2: 'missing' });
    expect(notices([a2], CONTIGUOUS)).toEqual({});
  });

  it('notices a device\'s events served in another order, and a number used twice', () => {
    const a1 = sequenced('a1', 'A', 1);
    const a2 = sequenced('a2', 'A', 2);
    expect(notices([a2, a1], CONTIGUOUS)).toEqual({ a1: 'order' });
    const other = sequenced('a2-other', 'A', 2, { idempotencyKey: 'key-other' });
    expect(notices([a1, a2, other], CONTIGUOUS)).toEqual({ 'a2-other': 'order' });
  });

  it('notices an event served before one it saw, or naming a seen event under another key', () => {
    const a1 = sequenced('a1', 'A', 1);
    const b1 = sequenced('b1', 'B', 1, { seenHeads: [{ deviceId: 'A', deviceSeq: 1, idempotencyKey: 'key-a1' }] });
    expect(notices([b1, a1], FORUM)).toEqual({ b1: 'order' });
    const forked = sequenced('b2', 'B', 2, { seenHeads: [{ deviceId: 'A', deviceSeq: 1, idempotencyKey: 'key-elsewhere' }] });
    expect(notices([a1, b1, forked], FORUM)).toEqual({ b2: 'order' });
  });

  it('notices a seen event that must be in the window but was not delivered', () => {
    const a1 = sequenced('a1', 'A', 1);
    const b1 = sequenced('b1', 'B', 1, { seenHeads: [{ deviceId: 'A', deviceSeq: 2, idempotencyKey: 'key-a2' }] });
    // A's earlier event is held, so A's second one would be too.
    expect(notices([a1, b1], CONTIGUOUS)).toEqual({ b1: 'missing' });
    // Nothing of A is held: it may be older than the window.
    expect(notices([b1], CONTIGUOUS)).toEqual({});
    expect(notices([b1], COMPLETE)).toEqual({ b1: 'missing' });
  });

  it('notices an event in an older layout served after v6 events', () => {
    const a1 = sequenced('a1', 'A', 1);
    const older = markMessageCryptoVerification({
      ...sequenced('old', 'A', 1, {}, 'pending'), deviceSeq: null, seenHeads: null, supersedes: null,
    }, true, true, false);
    expect(notices([older, a1], CONTIGUOUS)).toEqual({});
    expect(notices([a1, older], CONTIGUOUS)).toEqual({ old: 'order' });
    // Also after another device's v6 event: no event in an older layout is
    // written once the server takes v6.
    expect(notices([sequenced('b1', 'B', 1), older], CONTIGUOUS)).toEqual({ old: 'order' });
  });

  it('takes nothing from what was not signed: an unverified message fills its number but proves no order', () => {
    const a1 = sequenced('a1', 'A', 1);
    const unverified = sequenced('a2', 'A', 2, {}, false);
    const a3 = sequenced('a3', 'A', 3);
    expect(notices([a1, unverified, a3], CONTIGUOUS)).toEqual({});
    // A forged copy claiming an earlier number later in the window proves nothing.
    const forged = sequenced('forged', 'A', 1, {}, false);
    expect(notices([a1, a3, forged].filter(Boolean), FORUM)).toEqual({});
    // An event that cannot be read on this device still has a verified number.
    expect(hasSequencedEnvelope(markMessageKeyUnavailable(a3, true))).toBe(true);
  });

  it('lets an edit or a deletion whose check is pending fill its number', () => {
    const a1 = sequenced('a1', 'A', 1);
    const pendingEdit = sequenced('a2', 'A', 2, { type: 'edit', ...editOf('a1'), supersedes: 'key-a1' }, 'pending');
    const a3 = sequenced('a3', 'A', 3);
    expect(notices([a1, pendingEdit, a3], CONTIGUOUS)).toEqual({});
  });
});

describe('the projection shows what the client noticed', () => {
  it('marks the message after a gap, also when the gap is before an edit', () => {
    const a1 = sequenced('a1', 'A', 1);
    const a3 = sequenced('a3', 'A', 3);
    const shown = projectOrderedMessageEvents([a1, a3], CONTIGUOUS);
    expect(shown.map((message) => [message.id, message.sequenceNotice])).toEqual([['a1', undefined], ['a3', 'missing']]);

    const edit = sequenced('a4', 'A', 4, { type: 'edit', ...editOf('a1'), supersedes: 'key-a1', content: 'edited' });
    const afterEdit = projectOrderedMessageEvents([a1, edit, sequenced('b1', 'B', 1)], CONTIGUOUS);
    // a2 and a3 are missing before the edit; the next message carries it.
    expect(afterEdit.map((message) => [message.id, message.sequenceNotice])).toEqual([['a1', undefined], ['b1', 'missing']]);
    // With nothing after it, the newest message carries it.
    const atEnd = projectOrderedMessageEvents([a1, edit], CONTIGUOUS);
    expect(atEnd.map((message) => [message.id, message.sequenceNotice, message.content])).toEqual([['a1', 'missing', 'edited']]);
  });

  it('applies v6 edits in the order they replace each other, whatever order the server chose', () => {
    const base = sequenced('m', 'A', 1, { content: 'v1' });
    const first = sequenced('e1', 'A', 2, { type: 'edit', ...editOf('m'), supersedes: 'key-m', content: 'v2' });
    const second = sequenced('e2', 'A', 3, { type: 'edit', ...editOf('m'), supersedes: 'key-e1', content: 'v3' });
    const honest = projectOrderedMessageEvents([base, first, second], FORUM);
    expect(honest.map((message) => [message.content, message.editUncertain])).toEqual([['v3', undefined]]);
    // Served the other way round, the newer edit still wins (and the order is noticed).
    const swapped = projectOrderedMessageEvents([base, second, first], FORUM);
    expect(swapped.map((message) => [message.content, message.sequenceNotice])).toEqual([['v3', 'order']]);
  });

  it('applies a v6 edit served before its message once the message is there', () => {
    const base = sequenced('m', 'A', 1, { content: 'v1' });
    const first = sequenced('e1', 'A', 2, { type: 'edit', ...editOf('m'), supersedes: 'key-m', content: 'v2' });
    const shown = projectOrderedMessageEvents([first, base], FORUM);
    expect(shown.map((message) => [message.content, message.sequenceNotice, message.editUncertain])).toEqual([['v2', 'order', undefined]]);
  });

  it('shows that the latest version is unknown when an edit in between was withheld', () => {
    const base = sequenced('m', 'A', 1, { content: 'v1' });
    const second = sequenced('e2', 'A', 3, { type: 'edit', ...editOf('m'), supersedes: 'key-e1', content: 'v3' });
    const shown = projectOrderedMessageEvents([base, second], FORUM);
    expect(shown.map((message) => [message.content, message.editUncertain])).toEqual([['v1', true]]);
  });

  it('never puts back an older version: a second edit of a replaced version stays aside', () => {
    const base = sequenced('m', 'A', 1, { content: 'v1' });
    const first = sequenced('e1', 'A', 2, { type: 'edit', ...editOf('m'), supersedes: 'key-m', content: 'v2' });
    const rival = sequenced('e1b', 'B', 1, { type: 'edit', ...editOf('m'), supersedes: 'key-m', content: 'other v2' });
    const shown = projectOrderedMessageEvents([base, first, rival], FORUM);
    expect(shown.map((message) => [message.content, message.editUncertain])).toEqual([['v2', true]]);
  });

  it('keeps applying edits signed before v6 in the order served', () => {
    const base = sequenced('m', 'A', 1, { content: 'v1' });
    const older = markMessageCryptoVerification({
      ...sequenced('old-edit', 'A', 1, { type: 'edit', ...editOf('m'), content: 'v2' }, 'pending'),
      deviceSeq: null, seenHeads: null, supersedes: null,
    }, true, true, false);
    const after = sequenced('e', 'A', 2, { type: 'edit', ...editOf('m'), supersedes: 'key-old-edit', content: 'v3' });
    expect(projectOrderedMessageEvents([base, older, after], FORUM).map((message) => message.content)).toEqual(['v3']);
  });

  it('keeps the v6 marker when a copy of the same event is merged', () => {
    const a1 = sequenced('a1', 'A', 1);
    const copy = { ...a1 };
    for (const merged of [mergeMessageEvents([a1], [copy]), mergeMessageEvents([copy], [a1])]) {
      expect(hasSequencedEnvelope(merged[0])).toBe(true);
    }
  });
});

describe('numbering this device\'s events', () => {
  const device = { userId: 'user-1', deviceId: 'A' };

  it('starts at 1 and continues above its own events in the window', () => {
    expect(nextDeviceSequence(device, 'channel-1', [])).toBe(1);
    expect(nextDeviceSequence(device, 'channel-1', [sequenced('a1', 'A', 1), sequenced('a2', 'A', 2), sequenced('b5', 'B', 5)])).toBe(3);
  });

  it('ignores a number it cannot trust: an unsigned copy of its own event', () => {
    expect(nextDeviceSequence(device, 'channel-1', [sequenced('a9', 'A', 9, {}, false)])).toBe(1);
  });

  it('remembers the highest stored number after a restart, and only raises it from the server', () => {
    const stored = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => void stored.set(key, value),
    });
    noteStoredSequence(device, 'channel-1', 7);
    resetDeviceSequences();
    expect(nextDeviceSequence(device, 'channel-1', [])).toBe(8);
    noteExpectedSequence(device, 'channel-1', 3);
    expect(nextDeviceSequence(device, 'channel-1', [])).toBe(8);
    noteExpectedSequence(device, 'channel-1', 12);
    expect(nextDeviceSequence(device, 'channel-1', [])).toBe(12);
    expect(nextDeviceSequence(device, 'channel-2', [])).toBe(1);
  });

  it('names the newest verified event of another device as seen', () => {
    const events = [sequenced('b1', 'B', 1), sequenced('a1', 'A', 1), sequenced('c1', 'C', 1, {}, false), sequenced('b2', 'B', 2)];
    expect(seenHeadsOf(events, 'A')).toEqual([{ deviceId: 'B', deviceSeq: 2, idempotencyKey: 'key-b2' }]);
    expect(seenHeadsOf([sequenced('a1', 'A', 1)], 'A')).toEqual([]);
  });
});
