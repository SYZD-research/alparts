// M9: runs the real client message projector (packages/client/src/stores/
// message-projector.ts) on every history a malicious server can build from a
// fixed set of genuine signed events, within the bounds below, and checks what
// the client would show against what the authors signed.
//
// The server cannot forge a signature or an AEAD tag (EUF-CMA, INT-CTXT), so
// every event that verifies is a genuine envelope. It chooses which events to
// serve, their server ids (permuted among the served events, or a fresh id for
// a second copy), their createdAt, and in two deliveries (a page, then a later
// page or socket event that repeats some events). The client's verification
// step is the client's own choice of signed layouts (message-envelope.ts, as
// decryptMessages uses it) checked against the genuine signature; directory
// binding and AEAD pass for genuine envelopes. An edit or deletion that does
// not verify is dropped, a message is kept as one that could not be verified.
//
// The server also serves what no author signed (the fabrication pass, in the
// same bounds but with honest ids or two swapped, and no second delivery): events
// of other types (system, reaction, unknown), unsigned messages, edits and
// deletions, some of them before verification has finished, and a genuine
// message with its references changed, whose signature then fails (a message
// that could not be verified, with the references the server chose).
//
// The display rules are the client's: a quote shows quotedMessage (MessageItem),
// a post shows the replies belongsToPost accepts under the root served by id
// (ForumPostView), files open by attachment-crypto's binding (message id and
// the message's signed idempotency key) on a verified message.
//
// Protocol: in 'v5', every event that references another message is signed
// in v5, which also signs what its references name (the author and signed
// idempotency key of the edited, deleted or quoted message, and of the post's
// first message); the server serves that pair with each event and the client
// checks it (quotedMessage, belongsToPost, the projector's edit and delete
// rules). Events without references keep the older layout, as current clients
// sign them. In 'older', every event is in the older layout (v3/v4), which
// names targets by server id only; the client refuses it for references, and
// the second file is signed in the unbound v2 layout. The mutation
// 'accept-older-layouts' is the client before that refusal: references verify
// in the older layout too, and a v2 file opens for its message id.
//
// Input (stdin): { scenario: 'forum' | 'text', maxSecondDelivery: number, protocol: 'v5' | 'older', mutation? }
// Output: { histories, results: { [property]: { violations, example } } }
import { readFileSync } from 'node:fs';

const projector = await import('../../packages/client/src/stores/message-projector.ts');
const { signedEnvelopeCandidates, signedEnvelopeLayouts } = await import('../../packages/client/src/stores/message-envelope.ts');
const { isBoundMessageEnvelope, serializeMessageEnvelope } = await import('../../packages/shared/src/security/index.ts');
/** What decryptMessages puts in place of a message it cannot verify (services/message-display.ts). */
const UNVERIFIED_MESSAGE_MARKER = '[メッセージを検証できませんでした]';

type Message = Parameters<typeof projector.mergeMessageEvents>[0][number];

interface Genuine {
  name: string;
  type: 'message' | 'edit' | 'delete';
  authorId: string;
  key: string;
  refName: string | null;      // genuine target (edit, delete, quote)
  postName: string | null;     // forum: genuine post (null for a root)
  content: string;
  fileBinding?: 'v3' | 'v2';   // an attachment signed with this message
}

const input = JSON.parse(readFileSync(0, 'utf8')) as {
  scenario: 'forum' | 'text';
  maxSecondDelivery: number;
  protocol: 'v5' | 'older';
  mutation?: 'accept-older-layouts';
};
if (input.mutation !== undefined && input.mutation !== 'accept-older-layouts') throw new Error(`unknown mutation ${input.mutation}`);
const bound = input.protocol === 'v5';
const acceptOlder = input.mutation === 'accept-older-layouts';
const forum = input.scenario === 'forum';
const CHANNEL = '00000000-0000-4000-8000-0000000000c1';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

// Genuine events as written through an honest server. Ids are the honest ids.
// Genuine events, in the order an honest server stores them (by time).
const genuine: Genuine[] = forum
  ? [
    { name: 'P1', type: 'message', authorId: 'A', key: 'k-p1', refName: null, postName: null, content: 'post 1: vote yes' },
    { name: 'P2', type: 'message', authorId: 'A', key: 'k-p2', refName: null, postName: null, content: 'post 2: vote no' },
    { name: 'X1', type: 'message', authorId: 'B', key: 'k-x1', refName: null, postName: 'P1', content: 'reply to post 1: agreed' },
    { name: 'E1', type: 'edit', authorId: 'A', key: 'k-e1', refName: 'P1', postName: 'P1', content: 'post 1 (edited): vote yes!' },
    { name: 'D2', type: 'delete', authorId: 'A', key: 'k-d2', refName: 'P2', postName: 'P2', content: '' },
  ]
  : [
    { name: 'M1', type: 'message', authorId: 'A', key: 'k-m1', refName: null, postName: null, content: 'meet at 10', fileBinding: 'v3' },
    { name: 'M2', type: 'message', authorId: 'A', key: 'k-m2', refName: null, postName: null, content: 'cancelled', fileBinding: 'v2' },
    { name: 'Q3', type: 'message', authorId: 'B', key: 'k-q3', refName: 'M1', postName: null, content: 'ok, see you' },
    { name: 'E1', type: 'edit', authorId: 'A', key: 'k-e1', refName: 'M1', postName: null, content: 'meet at 11' },
    { name: 'D2', type: 'delete', authorId: 'A', key: 'k-d2', refName: 'M2', postName: null, content: '' },
  ];
const honestId = new Map(genuine.map((g, i) => [g.name, id(i + 1)]));
const byName = new Map(genuine.map((g) => [g.name, g]));

/** What a v5 envelope signs for a referenced event: its author and signed key. */
function bindingOf(name: string | null) {
  if (!name) return null;
  const target = byName.get(name)!;
  return { authorId: target.authorId, idempotencyKey: target.key };
}

/** Current clients sign v5 only for an event that references another message. */
const signsBound = (g: Genuine) => bound && (g.refName !== null || (forum && g.postName !== null));

function envelopeOf(g: Genuine) {
  return {
    type: g.type,
    channelId: CHANNEL,
    authorId: g.authorId,
    deviceId: `device-${g.authorId}`,
    keyVersion: 1,
    idempotencyKey: g.key,
    refMessageId: g.refName ? honestId.get(g.refName)! : null,
    broadcastMention: false,
    encryptedContent: g.type === 'delete' ? '' : `ct(${g.name})`,
    contentNonce: g.type === 'delete' ? '' : `n(${g.name})`,
    ...(forum ? { postId: g.postName ? honestId.get(g.postName)! : null } : {}),
    ...(signsBound(g) ? { refBinding: bindingOf(g.refName), ...(forum ? { postBinding: bindingOf(g.postName) } : {}) } : {}),
  };
}
// The genuine signature is a function of the signed bytes only.
const signatures = new Map(genuine.map((g) => [g.name, `sig(${serializeMessageEnvelope(envelopeOf(g) as never)})`]));
const signature = (g: Genuine) => signatures.get(g.name)!;

/** A genuine event as the server serves it under serverId, before the client verifies it. */
function wireEvent(g: Genuine, serverId: string, time: number): Message {
  const envelope = envelopeOf(g);
  return {
    id: serverId,
    channelId: envelope.channelId,
    authorId: g.authorId,
    author: { id: g.authorId, displayName: g.authorId },
    deviceId: envelope.deviceId,
    content: g.type === 'delete' ? '' : g.content,
    encryptedContent: envelope.encryptedContent,
    contentNonce: envelope.contentNonce,
    keyVersion: 1,
    signature: signature(g),
    broadcastMention: false,
    type: g.type,
    refMessageId: envelope.refMessageId,
    ...(forum ? { postId: envelope.postId } : {}),
    // The server serves what a v5 event's references name; a different pair
    // fails the signature, so a verified v5 event carries the signed one.
    ...(signsBound(g) ? { refBinding: envelope.refBinding, ...(forum ? { postBinding: envelope.postBinding } : {}) } : {}),
    reactions: [],
    isPinned: false,
    idempotencyKey: g.key,
    createdAt: new Date(Date.UTC(2026, 9, 1, 0, 0, time)).toISOString(),
  } as unknown as Message;
}

/**
 * What decryptMessages makes of a served event: verified (against the genuine
 * signature), a message kept as one that could not be verified, or dropped.
 */
function decide(event: Message): Message | null {
  // The client tries its signed layouts for this event against the genuine signature.
  const { older, bound: boundLayout } = signedEnvelopeLayouts(event, forum);
  const candidates = acceptOlder ? [boundLayout, older] : signedEnvelopeCandidates(event, forum);
  const layout = candidates.find((candidate) => {
    try {
      return `sig(${serializeMessageEnvelope(candidate)})` === event.signature;
    } catch {
      return false;
    }
  });
  if (!layout) {
    return event.type === 'message'
      ? projector.markMessageCryptoVerification({ ...event, content: UNVERIFIED_MESSAGE_MARKER }, false)
      : null;
  }
  return projector.markMessageCryptoVerification(event, true, isBoundMessageEnvelope(layout));
}
function served(g: Genuine, serverId: string, time: number): Message | null {
  return decide(wireEvent(g, serverId, time));
}
const verified = (event: Message | undefined) => Boolean(event) && projector.getMessageCryptoVerificationState(event!) === true;

function permutations<T>(items: T[]): T[][] {
  if (items.length <= 1) return [items];
  return items.flatMap((item, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]));
}
function subsets<T>(items: T[]): T[][] {
  return items.reduce<T[][]>((out, item) => out.concat(out.map((s) => [...s, item])), [[]]);
}

const results: Record<string, { violations: number; example: string[] | null }> = {};
const note = (property: string, trace: string[]) => {
  const entry = results[property] ??= { violations: 0, example: null };
  entry.violations++;
  if (!entry.example || trace.length < entry.example.length) entry.example = trace;
};
for (const property of [
  'MI-replay', 'MI-redate', 'MI-edit', 'MI-reply', 'MI-quote', 'MI-delete', 'MI-honest',
  'MI-file-v3', 'MI-file-v2', 'MI-latest', 'MI-forged', 'MI-unverified',
]) {
  results[property] = { violations: 0, example: null };
}

let histories = 0;
const names = genuine.map((g) => g.name);
for (const chosen of subsets(names)) {
  if (chosen.length === 0) continue;
  for (const ids of permutations(chosen.map((n) => honestId.get(n)!))) {
    for (const order of permutations(chosen)) {
      // Optional second delivery: repeat up to N events under the same id with a later time
      // (re-dating), or under a fresh id (replay as a new event).
      const repeats: Array<Array<{ name: string; fresh: boolean }>> = [[]];
      if (input.maxSecondDelivery > 0) {
        for (const name of chosen) {
          repeats.push([{ name, fresh: false }], [{ name, fresh: true }]);
        }
      }
      for (const repeat of repeats) {
        histories++;
        const idOf = new Map(chosen.map((n, i) => [n, ids[i]]));
        const timeOf = new Map(order.map((n, i) => [n, i + 1]));
        const first = chosen.flatMap((n) => served(byName.get(n)!, idOf.get(n)!, timeOf.get(n)!) ?? []);
        const second = repeat.flatMap(({ name, fresh }) => served(byName.get(name)!, fresh ? id(90) : idOf.get(name)!, 50) ?? []);
        const trace = [
          ...chosen.map((n) => `serve ${n} (honest id ${honestId.get(n)!.slice(-2)}) as id ${idOf.get(n)!.slice(-2)} at t${timeOf.get(n)}`),
          ...repeat.map(({ name, fresh }) => `serve ${name} again as ${fresh ? 'a new id 90' : 'the same id'} at t50`),
        ];
        const merged = projector.mergeMessageEvents(first, second);
        const shown = projector.projectOrderedMessageEvents(merged);
        check(shown, merged, idOf, trace, repeat.length > 0);
        // The history an honest server serves: everything once, under its own
        // id, in the order it was written (in v5; the older layout is refused).
        if (
          bound && repeat.length === 0 && chosen.length === genuine.length
          && chosen.every((n) => idOf.get(n) === honestId.get(n)) && order.every((n, i) => n === names[i])
        ) checkHonest(shown, trace);
        // MI-redate: delivering an event the client already holds again, under
        // the same id, changes nothing the client shows.
        if (repeat.length && repeat.every(({ fresh }) => !fresh)) {
          const before = projector.projectOrderedMessageEvents(projector.mergeMessageEvents(first));
          const view = (list: typeof shown) => JSON.stringify(list.map((m) => [m.id, m.type, m.content]));
          if (view(before) !== view(shown)) {
            note('MI-redate', [...trace, `=> shown before: ${view(before)}`, `=> shown after: ${view(shown)}`]);
          }
        }
      }
    }
  }
}

// The fabrication pass: what the server serves besides genuine events (see the
// header). Every order, with honest ids or two events under each other's ids,
// and no second delivery. It must exercise what MI-unverified is about, or the
// property would hold for want of a case: a tampered message with a quote, a
// place under a post, or a verified edit the client could have applied.
const witnessed = { quote: 0, post: 0, edit: 0 };
for (const chosen of subsets(names)) {
  if (chosen.length === 0) continue;
  const honest = chosen.map((n) => honestId.get(n)!);
  const swapped = chosen.flatMap((_, i) => chosen.slice(i + 1).map((__, j) => {
    const ids = [...honest];
    [ids[i], ids[i + 1 + j]] = [ids[i + 1 + j], ids[i]];
    return ids;
  }));
  for (const ids of [honest, ...swapped]) {
    for (const order of permutations(chosen)) {
      const idOf = new Map(chosen.map((n, i) => [n, ids[i]]));
      const timeOf = new Map(order.map((n, i) => [n, i + 1]));
      const events = chosen.map((n) => wireEvent(byName.get(n)!, idOf.get(n)!, timeOf.get(n)!));
      const trace = chosen.map((n) => `serve ${n} (honest id ${honestId.get(n)!.slice(-2)}) as id ${idOf.get(n)!.slice(-2)} at t${timeOf.get(n)}`);
      histories++;
      checkMadeUp(events.flatMap((event) => decide(event) ?? []), chosen, idOf, trace);
      for (const change of tamperings(chosen, idOf)) {
        const original = events[chosen.indexOf(change.name)];
        const altered = { ...original, ...change.fields } as Message;
        if (JSON.stringify(altered) === JSON.stringify(original)) continue;
        histories++;
        const held = events.flatMap((event, i) => decide(chosen[i] === change.name ? altered : event) ?? []);
        const { merged, shown } = project(held);
        check(shown, merged, idOf, [...trace, `serve ${change.name} with ${change.what}`], true);
        for (const base of merged.filter((e) => e.type === 'message' && !verified(e))) {
          if (base.refMessageId && shown.some((m) => m.id === base.refMessageId)) witnessed.quote++;
          if (forum && base.postId && shown.some((m) => m.id === base.postId)) witnessed.post++;
          if (merged.some((e) => e.type === 'edit' && verified(e) && e.refMessageId === base.id && e.authorId === base.authorId
            && (!e.refBinding || e.refBinding.idempotencyKey === base.idempotencyKey))) witnessed.edit++;
        }
      }
    }
  }
}
// Edits are refused in the older layout, so only v5 (and the control) has a verified edit to apply.
const unexercised = Object.entries({
  quote: witnessed.quote,
  ...(forum ? { post: witnessed.post } : {}),
  ...(bound || acceptOlder ? { edit: witnessed.edit } : {}),
}).filter(([, count]) => count === 0).map(([what]) => what);
if (unexercised.length) {
  throw new Error(`the fabrication pass never served a tampered message with a ${unexercised.join(' or ')} the client could have honoured`);
}

type Shown = ReturnType<typeof projector.projectOrderedMessageEvents>;

function project(...batches: Message[][]) {
  const merged = projector.mergeMessageEvents(...batches);
  return { merged, shown: projector.projectOrderedMessageEvents(merged) };
}

/** An event nobody signed, as the server makes it up about the event served under about.id. */
function madeUp(type: string, serverId: string, about: { name: string; id: string } | null, content: string, signed = false): Message {
  return {
    id: serverId,
    channelId: CHANNEL,
    authorId: about ? byName.get(about.name)!.authorId : 'A',
    author: { id: 'A', displayName: 'A' },
    deviceId: signed ? 'device-A' : null,
    content,
    encryptedContent: '',
    contentNonce: '',
    keyVersion: 1,
    signature: signed ? 'sig(made up)' : null,
    broadcastMention: true,
    type,
    refMessageId: about?.id ?? null,
    ...(forum ? { postId: about?.id ?? null } : {}),
    // The server copies the pair of the event it names, as a v5 event would carry it.
    refBinding: bindingOf(about?.name ?? null),
    ...(forum ? { postBinding: bindingOf(about?.name ?? null) } : {}),
    reactions: [],
    isPinned: false,
    idempotencyKey: `made-up-${serverId}`,
    createdAt: new Date(Date.UTC(2026, 9, 1, 0, 0, 50)).toISOString(),
  } as unknown as Message;
}

/**
 * What the server makes up about each served message. The client must ignore
 * the first kind (types it does not store, and an edit and a deletion that have
 * not verified), and must show no text, quote or place for the second (an
 * unsigned message: not verified yet, or verified to fail).
 */
function madeUpEvents(chosen: string[], idOf: Map<string, string>): { ignored: Message[]; unsigned: Message[] } {
  const ignored: Message[] = [];
  const unsigned: Message[] = [];
  let serial = 0;
  const fresh = () => id(100 + serial++);
  for (const name of chosen) {
    const about = { name, id: idOf.get(name)! };
    for (const type of ['system', 'reaction', 'announcement']) {
      ignored.push(madeUp(type, fresh(), about, type === 'reaction' ? '👍' : 'server injected'));
    }
    ignored.push(madeUp('edit', fresh(), about, 'server injected edit'), madeUp('delete', fresh(), about, ''));
    // Under the id of a served event, where it would be taken for a second copy of it.
    ignored.push(madeUp('system', about.id, null, 'replaces the message'));
    unsigned.push(madeUp('message', fresh(), about, 'server injected'), decide(madeUp('message', fresh(), about, 'server injected', true))!);
  }
  return { ignored, unsigned };
}

/**
 * Each served message with its references changed to name another served
 * event, or none: its signature then fails, and the client keeps it as a
 * message it could not verify, carrying the references the server chose.
 */
function tamperings(chosen: string[], idOf: Map<string, string>) {
  const changes: Array<{ name: string; what: string; fields: Record<string, unknown> }> = [];
  for (const name of chosen) {
    if (byName.get(name)!.type !== 'message') continue;
    for (const target of [...chosen.filter((n) => n !== name), null]) {
      const targetId = target === null ? null : idOf.get(target)!;
      changes.push({ name, what: `a quote of ${target ?? 'nothing'}`, fields: { refMessageId: targetId, refBinding: bindingOf(target) } });
      if (forum) changes.push({ name, what: `a place under ${target ?? 'nothing'}`, fields: { postId: targetId, postBinding: bindingOf(target) } });
    }
  }
  return changes;
}

/** Everything the client shows of a history: each message with its text, reactions, quote and the posts it is listed under. */
function appearance(shown: Shown, merged: Message[], skip: ReadonlySet<string> = new Set()): string {
  const roots = shown.filter((m) => !m.postId && m.type !== 'delete');
  return JSON.stringify([
    merged.some(projector.hasAuthenticatedEnvelopeConflict),
    shown.filter((m) => !skip.has(m.id)).map((m) => {
      const quoted = m.refMessageId ? projector.quotedMessage(m, shown) : undefined;
      return [
        m.id, m.type, m.content, m.reactions,
        m.refMessageId ? (quoted === undefined ? 'not loaded' : quoted?.id ?? 'cannot be shown') : null,
        forum ? roots.filter((root) => projector.belongsToPost(m, root)).map((root) => root.id) : [],
      ];
    }),
  ]);
}

/**
 * MI-forged: serving what the server made up (other types, an unverified edit
 * and deletion) changes nothing the client shows, and an unsigned message
 * changes nothing about the others; MI-unverified: it shows nothing itself.
 */
function checkMadeUp(first: Message[], chosen: string[], idOf: Map<string, string>, trace: string[]) {
  const { ignored, unsigned } = madeUpEvents(chosen, idOf);
  const without = project(first);
  const expected = appearance(without.shown, without.merged);
  const withIgnored = project(first, ignored);
  const afterIgnored = appearance(withIgnored.shown, withIgnored.merged);
  if (afterIgnored !== expected) {
    note('MI-forged', [...trace, '=> serving events of other types, or an edit and a deletion nobody signed, changes what is shown',
      `=> shown without: ${expected}`, `=> shown with: ${afterIgnored}`]);
  }
  const withUnsigned = project(first, unsigned);
  const afterUnsigned = appearance(withUnsigned.shown, withUnsigned.merged, new Set(unsigned.map((event) => event.id)));
  if (afterUnsigned !== expected) {
    note('MI-forged', [...trace, '=> serving messages nobody signed changes what is shown of the others',
      `=> shown without: ${expected}`, `=> shown with: ${afterUnsigned}`]);
  }
  checkUnverified(withUnsigned.shown, withUnsigned.merged, trace);
}

/**
 * MI-unverified: a message that did not verify, or has not yet, shows no text,
 * not even that of a verified edit of it, no quote and no place under a post.
 * Its references are whatever the server served.
 */
function checkUnverified(shown: Shown, merged: Message[], trace: string[]) {
  const roots = shown.filter((m) => !m.postId && m.type !== 'delete');
  for (const m of shown) {
    const base = merged.find((e) => e.id === m.id && e.type === 'message');
    if (!base || verified(base)) continue;
    const who = genuineOf(base)?.name ?? 'a message nobody signed';
    if (m.type === 'edit' || m.content !== '') note('MI-unverified', [...trace, `=> ${who} did not verify but shows "${m.content}"`]);
    const quoted = m.refMessageId ? projector.quotedMessage(m, shown) : undefined;
    if (quoted) note('MI-unverified', [...trace, `=> ${who} did not verify but is shown quoting "${quoted.content}"`]);
    if (forum && roots.some((root) => projector.belongsToPost(m, root))) {
      note('MI-unverified', [...trace, `=> ${who} did not verify but is listed under a post`]);
    }
  }
}

function genuineOf(message: { signature: string | null; idempotencyKey: string; authorId: string }): Genuine | undefined {
  return genuine.find((g) => g.authorId === message.authorId && g.key === message.idempotencyKey && signature(g) === message.signature);
}

/**
 * MI-honest: served honestly, every edit, deletion, quote and reply is shown
 * on what it was signed for (the checks that hold above are not met by
 * dropping events).
 */
function checkHonest(shown: ReturnType<typeof projector.projectOrderedMessageEvents>, trace: string[]) {
  const at = (name: string) => shown.find((m) => m.id === honestId.get(name));
  const fail = (what: string) => note('MI-honest', [...trace, `=> ${what}`]);
  for (const g of genuine) {
    if (g.type === 'edit') {
      const latest = genuine.filter((x) => x.type === 'edit' && x.refName === g.refName).at(-1)!;
      if (latest === g && at(g.refName!)?.content !== g.content) fail(`${g.name} is not shown on ${g.refName}`);
    } else if (g.type === 'delete') {
      if (at(g.refName!)?.type !== 'delete') fail(`${g.refName} is still shown after ${g.name}`);
    } else if (g.refName) {
      const quote = at(g.name);
      const target = quote && projector.quotedMessage(quote, shown);
      if (!target || target.id !== honestId.get(g.refName)) fail(`${g.name} does not show its quote of ${g.refName}`);
    } else if (g.postName) {
      const reply = at(g.name);
      const root = at(g.postName);
      if (!reply || !root || !projector.belongsToPost(reply, root)) fail(`${g.name} is not shown under ${g.postName}`);
    }
  }
}

function check(shown: ReturnType<typeof projector.projectOrderedMessageEvents>, merged: Message[], idOf: Map<string, string>,
  trace: string[], second: boolean) {
  checkUnverified(shown, merged, trace);
  const visible = shown.filter((m) => m.type !== 'delete' && m.content !== '');
  // MI-replay: one signed operation (channel, author, key) is shown at most once.
  const counts = new Map<string, number>();
  for (const m of visible) {
    const g = genuineOf(m);
    if (g) counts.set(g.name, (counts.get(g.name) ?? 0) + 1);
  }
  for (const [name, count] of counts) if (count > 1) note('MI-replay', [...trace, `=> ${name} is shown ${count} times`]);
  // MI-edit: edited content is shown on the message the edit was signed for.
  for (const m of visible) {
    if (m.type !== 'edit') continue;
    const edit = genuineOf(m);
    const base = merged.find((e) => e.id === m.id && e.type === 'message');
    const baseGenuine = base && genuineOf(base);
    if (edit && baseGenuine && edit.refName !== baseGenuine.name) {
      note('MI-edit', [...trace, `=> ${edit.name} ("${edit.content}") is shown on ${baseGenuine.name} ("${baseGenuine.content}")`]);
    }
  }
  // MI-reply (forum): replies are shown under the post they were signed for
  // (ForumPostView lists what belongsToPost accepts under the root by id).
  if (forum) {
    for (const root of shown.filter((m) => !m.postId && m.type !== 'delete')) {
      const rootBase = merged.find((e) => e.id === root.id && e.type === 'message');
      const rootGenuine = rootBase && genuineOf(rootBase);
      if (!rootGenuine) continue;
      for (const reply of shown.filter((m) => m.content !== '' && projector.belongsToPost(m, root))) {
        const replyBase = merged.find((e) => e.id === reply.id && e.type === 'message');
        // A reply the client could not verify is shown as such, not as the author's.
        const replyGenuine = verified(replyBase) && genuineOf(replyBase!);
        if (replyGenuine && replyGenuine.postName !== rootGenuine.name) {
          note('MI-reply', [...trace, `=> reply ${replyGenuine.name} (signed for ${replyGenuine.postName}) is shown under ${rootGenuine.name} ("${rootGenuine.content}")`]);
        }
      }
    }
  }
  // MI-quote: a quote shows the message it was signed for (MessageItem shows
  // what quotedMessage returns; null shows that the original cannot be shown).
  for (const m of visible) {
    if (m.type !== 'message' || !m.refMessageId) continue;
    // A quote the client could not verify is shown as such, not as the author's.
    const quoting = verified(merged.find((e) => e.id === m.id && e.type === 'message')) && genuineOf(m);
    const target = projector.quotedMessage(m, shown);
    const targetBase = target && merged.find((e) => e.id === target.id && e.type === 'message');
    const targetGenuine = targetBase && genuineOf(targetBase);
    if (quoting && targetGenuine && quoting.refName !== targetGenuine.name) {
      note('MI-quote', [...trace, `=> ${quoting.name} quotes ${quoting.refName} but is shown quoting ${targetGenuine.name} ("${targetGenuine.content}")`]);
    }
  }
  // MI-delete: a deletion removes only the message it was signed for.
  for (const m of shown.filter((x) => x.type === 'delete')) {
    const base = merged.find((e) => e.id === m.id && e.type === 'message');
    const baseGenuine = base && genuineOf(base);
    if (!baseGenuine) continue;
    const deletions = merged.filter((e) => e.type === 'delete' && e.refMessageId === m.id).flatMap((e) => genuineOf(e) ?? []);
    if (deletions.length && deletions.every((d) => d.refName !== baseGenuine.name)) {
      note('MI-delete', [...trace, `=> ${baseGenuine.name} ("${baseGenuine.content}") is removed by ${deletions.map((d) => `${d.name} (signed for ${d.refName})`).join(', ')}`]);
    }
  }
  // MI-file: an attachment opens only on the message it was signed with.
  for (const owner of genuine.filter((g) => g.fileBinding)) {
    const fileMessageId = honestId.get(owner.name)!;   // the manifest signs the honest id
    for (const m of shown.filter((x) => x.id === fileMessageId && x.type !== 'delete')) {
      // attachment-crypto uses the original (unedited) event under that id.
      const base = merged.find((e) => e.id === m.id && e.type === 'message');
      const baseGenuine = base && genuineOf(base);
      if (!baseGenuine || baseGenuine.name === owner.name) continue;
      // attachment-crypto opens a file only on a verified message, signed for its idempotency key;
      // the client before the refusal also opened an unbound (v2) file for the message id.
      const opens = verified(base) && (owner.fileBinding === 'v3' ? base!.idempotencyKey === owner.key : acceptOlder);
      if (opens) note(owner.fileBinding === 'v3' ? 'MI-file-v3' : 'MI-file-v2',
        [...trace, `=> the file signed with ${owner.name} opens on ${baseGenuine.name} ("${baseGenuine.content}")`]);
    }
  }
  // MI-latest (documented limit): with every genuine event served once under
  // its honest id, a message shows its latest edit (the server picks the order).
  if (bound && !second && idOf.size === genuine.length) {
    for (const g of genuine.filter((x) => x.type === 'message')) {
      const edits = genuine.filter((x) => x.type === 'edit' && x.refName === g.name);
      if (!edits.length || ![g, ...edits].every((x) => idOf.has(x.name))) continue;
      const allHonestIds = [...idOf.entries()].every(([n, v]) => v === honestId.get(n));
      if (!allHonestIds) continue;
      const m = shown.find((x) => x.id === honestId.get(g.name));
      if (m && m.content !== edits.at(-1)!.content && m.content !== '') {
        note('MI-latest', [...trace, `=> ${g.name} shows "${m.content}", not its latest edit`]);
      }
    }
  }
}

process.stdout.write(JSON.stringify({ histories, results }));
