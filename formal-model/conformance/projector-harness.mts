// M9: runs the real client message projector (packages/client/src/stores/
// message-projector.ts) on every history a malicious server can build from a
// fixed set of genuine signed events, within the bounds below, and checks what
// the client would show against what the authors signed.
//
// The server cannot forge a signature or an AEAD tag (EUF-CMA, INT-CTXT), so
// it only serves genuine envelopes. It chooses which events to serve, their
// server ids (permuted among the served events, or a fresh id for a second
// copy), their createdAt, and in two deliveries (a page, then a later page or
// socket event that repeats some events). The client's verification step is
// modeled as passing for every genuine envelope, which is what decryptMessages
// does for them (signature, directory binding, AEAD with the loaded channel's
// key).
//
// The display rules are the client's: a quote shows quotedMessage (MessageItem),
// a post shows the replies belongsToPost accepts under the root served by id
// (ForumPostView), files open by attachment-crypto's v3 binding (message id and
// the message's signed idempotency key) or the legacy v2 binding (message id).
//
// Protocol: in 'v5', every event that references another message is signed
// in v5, which also signs what its references name (the author and signed
// idempotency key of the edited, deleted or quoted message, and of the post's
// first message); the server serves that pair with each event and the client
// checks it (quotedMessage, belongsToPost, the projector's edit and delete
// rules). Events without references keep the older layout, as current clients
// sign them. In 'legacy', every event is in the older layout (v3/v4, still
// accepted from older clients), which names targets by server id only.
//
// Input (stdin): { scenario: 'forum' | 'text', maxSecondDelivery: number, protocol: 'v5' | 'legacy' }
// Output: { histories, results: { [property]: { violations, example } } }
import { readFileSync } from 'node:fs';

const projector = await import('../../packages/client/src/stores/message-projector.ts');
const { serializeMessageEnvelope } = await import('../../packages/shared/src/security/index.ts');

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
  protocol: 'v5' | 'legacy';
};
const bound = input.protocol === 'v5';
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

function served(g: Genuine, serverId: string, time: number): Message {
  const envelope = envelopeOf(g);
  const event = {
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
  return projector.markMessageCryptoVerification(event, true, signsBound(g));
}

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
for (const property of ['MI-replay', 'MI-redate', 'MI-edit', 'MI-reply', 'MI-quote', 'MI-delete', 'MI-honest', 'MI-file-v3', 'MI-file-v2', 'MI-latest']) {
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
        const first = chosen.map((n) => served(byName.get(n)!, idOf.get(n)!, timeOf.get(n)!));
        const second = repeat.map(({ name, fresh }) => served(byName.get(name)!, fresh ? id(90) : idOf.get(name)!, 50));
        const trace = [
          ...chosen.map((n) => `serve ${n} (honest id ${honestId.get(n)!.slice(-2)}) as id ${idOf.get(n)!.slice(-2)} at t${timeOf.get(n)}`),
          ...repeat.map(({ name, fresh }) => `serve ${name} again as ${fresh ? 'a new id 90' : 'the same id'} at t50`),
        ];
        const merged = projector.mergeMessageEvents(first, second);
        const shown = projector.projectOrderedMessageEvents(merged);
        check(shown, merged, idOf, trace, repeat.length > 0);
        // The history an honest server serves: everything once, under its own
        // id, in the order it was written.
        if (
          repeat.length === 0 && chosen.length === genuine.length
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
      for (const reply of shown.filter((m) => m.type !== 'reaction' && m.content !== '' && projector.belongsToPost(m, root))) {
        const replyBase = merged.find((e) => e.id === reply.id && e.type === 'message');
        const replyGenuine = replyBase && genuineOf(replyBase);
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
    const quoting = genuineOf(m);
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
      const opens = owner.fileBinding === 'v2' || base!.idempotencyKey === owner.key;
      if (opens) note(owner.fileBinding === 'v3' ? 'MI-file-v3' : 'MI-file-v2',
        [...trace, `=> the file signed with ${owner.name} opens on ${baseGenuine.name} ("${baseGenuine.content}")`]);
    }
  }
  // MI-latest (documented limit): with every genuine event served once under
  // its honest id, a message shows its latest edit (the server picks the order).
  if (!second && idOf.size === genuine.length) {
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
