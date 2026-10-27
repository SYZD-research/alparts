// M10: runs the real client order checks (packages/client/src/stores/
// message-projector.ts: analyzeEventOrder and the projection's v6 edit chain)
// on every history a malicious server can build from a fixed set of genuine
// v6 events, and checks what the client shows against what the devices wrote.
//
// The server cannot forge a signature (EUF-CMA), so it serves genuine
// envelopes only (M9 covers what it makes up or alters). It chooses which
// events to serve and in which order, and the client loads them as one of
// three windows: the whole channel from its first event ('complete'), the
// newest events only ('suffix': a run of consecutive events that does not
// reach the start), or a forum, whose posts are loaded one by one
// ('forum': no run of consecutive events at all). The client verifies each
// served event in the layouts it accepts (message-envelope.ts) against the
// genuine signature.
//
// Genuine history (text channel, three devices; heads are what each device
// had received when it wrote, as clients pick them: the newest event of
// another device):
//   A1  A message  #1
//   B1  B message  #1  saw A1
//   A2  A edit of A1 #2  saw B1  (replaces A1)
//   C1  C message  #1  saw B1
//   B2  B message  #2  saw A2
//   A3  A message  #3  saw B2
//   A4  A edit of A1 #4  saw C1  (replaces A2)
// "X happened before Y" (hb) is the transitive closure of: same device with a
// lower number, and Y's writer had received X ("seen" above, with everything
// that happened before it). Each event names as heads the newest event of
// every other device among what happened before it, as clients pick them
// (up to eight devices; three here).
//
// Mutation 'no-sequence' is the client before v6 (the events carry no number,
// heads or replaced version): the control for MO-order and MO-drop.
// Mutation 'single-head' is the phase 1 client, which named only the one
// event in "seen" as its head: the control for MO-order-hidden.
// Mutation 'memory' is a member who received the whole honest history before
// (its browser remembers each device's newest event, channel-memory.ts) and
// is then served any subset in any order.
// Mutation 'split' is the server that claimed to refuse an event it stored:
// device A signed a second event A2x under number 2. Each member is served
// one of the two (a split view); a member served both must notice.
//
// Input (stdin): { mutation?: 'no-sequence' | 'split' | 'single-head' | 'memory' }
// Output: { histories, results: { [property]: { violations, example } } }
import { readFileSync } from 'node:fs';

const projector = await import('../../packages/client/src/stores/message-projector.ts');
const { signedEnvelopeCandidates } = await import('../../packages/client/src/stores/message-envelope.ts');
const { isBoundMessageEnvelope, isSequencedMessageEnvelope, serializeMessageEnvelope } = await import('../../packages/shared/src/security/index.ts');

type Message = Parameters<typeof projector.mergeMessageEvents>[0][number];
type Window = 'complete' | 'suffix' | 'forum';

interface Genuine {
  name: string;
  device: 'A' | 'B' | 'C';
  seq: number;
  type: 'message' | 'edit';
  refName: string | null;
  /** An edit: the version it replaces. */
  replaces?: string;
  seen: string | null;
  content: string;
}

const input = JSON.parse(readFileSync(0, 'utf8')) as { mutation?: 'no-sequence' | 'split' | 'single-head' | 'memory' };
if (input.mutation !== undefined && !['no-sequence', 'split', 'single-head', 'memory'].includes(input.mutation)) {
  throw new Error(`unknown mutation ${input.mutation}`);
}
const unsequenced = input.mutation === 'no-sequence';
const singleHead = input.mutation === 'single-head';
const channelMemory = await import('../../packages/client/src/stores/channel-memory.ts');
const CHANNEL = '00000000-0000-4000-8000-0000000000c1';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

const genuine: Genuine[] = [
  { name: 'A1', device: 'A', seq: 1, type: 'message', refName: null, seen: null, content: 'meet at 10' },
  { name: 'B1', device: 'B', seq: 1, type: 'message', refName: null, seen: 'A1', content: 'ok' },
  { name: 'A2', device: 'A', seq: 2, type: 'edit', refName: 'A1', replaces: 'A1', seen: 'B1', content: 'meet at 11' },
  { name: 'C1', device: 'C', seq: 1, type: 'message', refName: null, seen: 'B1', content: 'me too' },
  { name: 'B2', device: 'B', seq: 2, type: 'message', refName: null, seen: 'A2', content: '11 is fine' },
  { name: 'A3', device: 'A', seq: 3, type: 'message', refName: null, seen: 'B2', content: 'see you' },
  { name: 'A4', device: 'A', seq: 4, type: 'edit', refName: 'A1', replaces: 'A2', seen: 'C1', content: 'meet at 11:30' },
];
// The second event under A's number 2 (mutation 'split' only).
const forkedA2: Genuine = { name: 'A2x', device: 'A', seq: 2, type: 'message', refName: null, seen: 'B1', content: 'cancelled' };
const all = [...genuine, forkedA2];
const byName = new Map(all.map((g) => [g.name, g]));
const keyOf = (name: string) => `k-${name.toLowerCase()}`;
const honestId = new Map(all.map((g, i) => [g.name, id(i + 1)]));
const authorOf = (g: Genuine) => `user-${g.device}`;

/** hb: same device, lower number; or named as seen (with what happened before it). */
function happenedBefore(events: Genuine[]): Map<string, Set<string>> {
  const before = new Map(events.map((g) => [g.name, new Set<string>()]));
  let changed = true;
  const direct = (g: Genuine) => [
    ...events.filter((x) => x.device === g.device && x.seq < g.seq).map((x) => x.name),
    ...(g.seen ? [g.seen] : []),
  ];
  while (changed) {
    changed = false;
    for (const g of events) {
      const set = before.get(g.name)!;
      for (const x of direct(g)) {
        for (const y of [x, ...(before.get(x) ?? [])]) {
          if (!set.has(y)) {
            set.add(y);
            changed = true;
          }
        }
      }
    }
  }
  return before;
}

/** What happened before each event (the fork A2x has its own past). */
const pastOf = new Map<string, Set<string>>([
  ...happenedBefore(genuine),
  ['A2x', happenedBefore([...genuine.slice(0, 2), forkedA2]).get('A2x')!],
]);

/** The heads an event names: the newest event of each other device in its past (phase 1: only "seen"). */
function headsOf(g: Genuine): Genuine[] {
  if (singleHead) return g.seen ? [byName.get(g.seen)!] : [];
  const past = [...pastOf.get(g.name)!].map((name) => byName.get(name)!).filter((x) => x.device !== g.device);
  return (['A', 'B', 'C'] as const).flatMap((device) => {
    const newest = past.filter((x) => x.device === device).sort((x, y) => y.seq - x.seq)[0];
    return newest ? [newest] : [];
  });
}

function envelopeOf(g: Genuine) {
  return {
    type: g.type,
    channelId: CHANNEL,
    authorId: authorOf(g),
    deviceId: `device-${g.device}`,
    keyVersion: 1,
    idempotencyKey: keyOf(g.name),
    refMessageId: g.refName ? honestId.get(g.refName)! : null,
    broadcastMention: false,
    encryptedContent: `ct(${g.name})`,
    contentNonce: `n(${g.name})`,
    refBinding: g.refName ? { authorId: authorOf(byName.get(g.refName)!), idempotencyKey: keyOf(g.refName) } : null,
    ...(unsequenced ? {} : {
      deviceSeq: g.seq,
      seenHeads: headsOf(g).map((head) => ({ deviceId: `device-${head.device}`, deviceSeq: head.seq, idempotencyKey: keyOf(head.name) })),
      supersedes: g.type === 'edit' ? keyOf(g.replaces!) : null,
    }),
  };
}
const signatureOf = (g: Genuine) => `sig(${serializeMessageEnvelope(envelopeOf(g) as never)})`;

/** A genuine event as the server serves it at a time it picks, verified the way decryptMessages does. */
function served(g: Genuine, time: number): Message {
  const envelope = envelopeOf(g);
  const event = {
    ...envelope,
    id: honestId.get(g.name)!,
    author: { id: authorOf(g), displayName: g.device },
    content: g.content,
    signature: signatureOf(g),
    reactions: [],
    isPinned: false,
    createdAt: new Date(Date.UTC(2026, 9, 1, 0, 0, time)).toISOString(),
  } as unknown as Message;
  const layout = signedEnvelopeCandidates(event, false).find((candidate) => {
    try {
      return `sig(${serializeMessageEnvelope(candidate)})` === event.signature;
    } catch {
      return false;
    }
  });
  if (!layout) throw new Error(`${g.name} does not verify in any layout the client accepts`);
  return projector.markMessageCryptoVerification(event, true, isBoundMessageEnvelope(layout), isSequencedMessageEnvelope(layout));
}

function permutations<T>(items: T[]): T[][] {
  if (items.length <= 1) return [items];
  return items.flatMap((item, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]));
}
function subsets<T>(items: T[]): T[][] {
  return items.reduce<T[][]>((out, item) => out.concat(out.map((s) => [...s, item])), [[]]);
}

/** What a member's browser remembers after receiving these events (the real channel-memory module). */
let memorySerial = 0;
function rememberedAfter(events: Genuine[]) {
  const user = `member-${memorySerial++}`;
  channelMemory.rememberHeads(user, CHANNEL, events.map((g, i) => served(g, i + 1)));
  return channelMemory.rememberedHeads(user, CHANNEL);
}

const PROPERTIES = [
  'MO-honest', 'MO-honest-suffix', 'MO-honest-forum', 'MO-forged-number', 'MO-order', 'MO-order-complete', 'MO-order-hidden', 'MO-drop', 'MO-edit', 'MO-tail', 'MO-suffix',
  'MO-forum', 'MO-split', 'MO-split-seen', 'MO-split-named', 'MO-split-remembered', 'MO-rollback', 'MO-rollback-page',
];
const results: Record<string, { violations: number; example: string[] | null }> = Object.fromEntries(
  PROPERTIES.map((property) => [property, { violations: 0, example: null }]),
);
const note = (property: string, trace: string[]) => {
  const entry = results[property];
  entry.violations++;
  if (!entry.example || trace.length < entry.example.length) entry.example = trace;
};

const WINDOWS: Record<Window, projectorWindow> = {
  complete: { contiguous: true, complete: true },
  suffix: { contiguous: true, complete: false },
  forum: { contiguous: false, complete: false },
};
type projectorWindow = Parameters<typeof projector.projectOrderedMessageEvents>[1] & object;

/**
 * An event nobody signed that claims a number of a device: it fails the
 * signature, so the client keeps it as a message it could not verify.
 */
function forgedClaim(device: 'A' | 'B' | 'C', deviceSeq: number, time: number): Message {
  return projector.markMessageCryptoVerification({
    id: id(200 + time), channelId: CHANNEL, authorId: `user-${device}`, author: { id: `user-${device}`, displayName: device },
    deviceId: `device-${device}`, content: '[unverified]', encryptedContent: 'ct(forged)', contentNonce: 'n(forged)',
    keyVersion: 1, signature: 'sig(forged)', broadcastMention: false, type: 'message', refMessageId: null, refBinding: null,
    deviceSeq, seenHeads: [], supersedes: null, reactions: [], isPinned: false, idempotencyKey: `forged-${time}`,
    createdAt: new Date(Date.UTC(2026, 9, 1, 0, 0, time)).toISOString(),
  } as unknown as Message, false);
}

/** What the client shows of a served history in a window. */
function show(order: Genuine[], window: Window, extra: Message[] = [], remembered?: ReadonlyMap<string, { deviceSeq: number; keyPrefix: string }>) {
  const events = [...order.map((g, i) => served(g, i + 1)), ...extra];
  const merged = projector.mergeMessageEvents(events);
  // What MessageList shows: the messages with their notices, and the
  // channel's notice that no shown message carries.
  const { messages: shown, channelNotice } = projector.projectMessageWindow(merged, WINDOWS[window], remembered);
  const noticed = channelNotice !== null || shown.some((m) => m.sequenceNotice || m.editUncertain);
  return { shown, noticed, channelNotice };
}
const describe = (order: Genuine[], window: Window, view: { shown: ReturnType<typeof show>['shown']; channelNotice: string | null }) => [
  `${window} window: serve ${order.map((g) => g.name).join(', ') || 'nothing'}`,
  `=> shown: ${JSON.stringify(view.shown.map((m) => [m.content, m.sequenceNotice ?? null, m.editUncertain ?? null]))}`
    + (view.channelNotice ? `, channel: ${view.channelNotice}` : ''),
];

let histories = 0;
const hb = happenedBefore(genuine);
const honestOrder = genuine;

if (input.mutation === 'split') {
  // Each member is served one of A's two events under number 2, in the honest
  // order otherwise; one served both must notice.
  const withFork = [...genuine.slice(0, 2), forkedA2];
  for (const view of [genuine.slice(0, 3), withFork]) {
    histories++;
    const shownView = show(view, 'complete');
    const { noticed } = shownView;
    if (!noticed) note('MO-split', [...describe(view, 'complete', shownView), '=> nothing tells this member that others were shown another event under A #2']);
  }
  for (const order of permutations([...genuine.slice(0, 3), forkedA2])) {
    histories++;
    for (const window of ['complete', 'suffix', 'forum'] as Window[]) {
      const shownView = show(order, window);
      if (!shownView.noticed) note('MO-split-seen', [...describe(order, window, shownView), '=> both events under A #2 are shown, and nothing says so']);
    }
  }
  // Served the fork, and a later event whose writer received the other one
  // (B2 names A #2 under A2's key): the member notices, in any order.
  for (const order of permutations([genuine[0], genuine[1], forkedA2, byName.get('B2')!])) {
    histories++;
    for (const window of ['complete', 'suffix', 'forum'] as Window[]) {
      const shownView = show(order, window);
      if (!shownView.noticed) note('MO-split-named', [...describe(order, window, shownView), '=> a later event names the other A #2, and nothing says so']);
    }
  }
  // A member who received A2 before is later served A2x in its place.
  const remembered = rememberedAfter(genuine.slice(0, 3));
  for (const window of ['complete', 'suffix', 'forum'] as Window[]) {
    histories++;
    const shownView = show(withFork, window, [], remembered);
    if (!shownView.noticed) note('MO-split-remembered', [...describe(withFork, window, shownView), '=> A2 was received before, A2x is shown now, and nothing says so']);
  }
} else if (input.mutation === 'memory') {
  // MO-rollback: a member who received everything before notices any event
  // withheld later, whenever the window reaches the start or holds an
  // earlier event of its device (so the withheld one cannot be older than
  // the page); MO-rollback-page (limit): otherwise a page cannot tell.
  const remembered = rememberedAfter(genuine);
  for (const chosen of subsets(genuine)) {
    const withheld = genuine.filter((g) => !chosen.includes(g));
    if (withheld.length === 0) continue;
    for (const order of permutations(chosen)) {
      histories++;
      for (const window of ['complete', 'suffix'] as Window[]) {
        const shownView = show(order, window, [], remembered);
        if (shownView.noticed) continue;
        const traced = withheld.filter((x) => window === 'complete' || order.some((g) => g.device === x.device && g.seq < x.seq));
        if (traced.length) {
          note('MO-rollback', [...describe(order, window, shownView), `=> ${traced.map((g) => g.name).join(', ')} received before and withheld now, and nothing says so`]);
        } else {
          note('MO-rollback-page', [...describe(order, window, shownView), `=> ${withheld.map((g) => g.name).join(', ')} withheld; the page holds nothing of their devices before them`]);
        }
      }
    }
  }
} else {
  for (const chosen of subsets(genuine)) {
    if (chosen.length === 0) continue;
    const withheld = genuine.filter((g) => !chosen.includes(g));
    for (const order of permutations(chosen)) {
      histories++;
      const position = new Map(order.map((g, i) => [g.name, i]));
      // The served order puts something before an event that happened before it.
      const reordered = order.some((g) => [...hb.get(g.name)!].some((x) => position.has(x) && position.get(x)! > position.get(g.name)!));
      // ... as the served events themselves sign it: an event of the same
      // device with a higher number, or one naming as seen an event of x's
      // device numbered x or later, is served before x.
      const signsAfter = (y: Genuine, x: Genuine) => (y.device === x.device && y.seq > x.seq)
        || headsOf(y).some((head) => head.device === x.device && head.seq >= x.seq);
      const reorderedDirectly = order.some((y, i) => order.slice(i + 1).some((x) => signsAfter(y, x)));
      // A withheld event happened before a served one.
      const withheldPast = withheld.filter((x) => order.some((g) => hb.get(g.name)!.has(x.name)));
      // A withheld event nothing served happened after (the device's newest events).
      const withheldTail = withheld.filter((x) => !order.some((g) => hb.get(g.name)!.has(x.name)));
      const honestRun = order.every((g, i) => i === 0 || genuine.indexOf(g) === genuine.indexOf(order[i - 1]) + 1);
      for (const window of ['complete', 'suffix', 'forum'] as Window[]) {
        const shownView = show(order, window);
        const { shown, noticed } = shownView;
        const trace = describe(order, window, shownView);
        // MO-order: in any window, a served order against what the served events sign is noticed.
        if (reorderedDirectly && !noticed) note('MO-order', [...trace, '=> served against the order the events sign, and nothing says so']);
        if (window === 'complete' && reordered && !noticed) {
          note('MO-order-complete', [...trace, '=> served out of the order the events were written, and nothing says so']);
        }
        // MO-order-hidden (limit): a page or a forum, with the event in between withheld.
        if (window !== 'complete' && reordered && !reorderedDirectly && !noticed) {
          note('MO-order-hidden', [...trace, '=> served out of order with what shows it withheld, and nothing says so']);
        }
        if (window === 'complete') {
          // MO-drop: in a complete window, withholding what a served event came after is noticed.
          if (withheldPast.length && !noticed) {
            note('MO-drop', [...trace, `=> ${withheldPast.map((g) => g.name).join(', ')} withheld, and nothing says so`]);
          }
          // MO-forged-number: unsigned events claiming numbers of a device,
          // anywhere in the history, do not hide a withheld event.
          if (withheldPast.length && noticed) {
            for (const x of withheldPast) {
              for (const claimed of [x.seq, x.seq + 1, 1_000_000]) {
                for (let slot = 0; slot <= order.length; slot += 1) {
                  histories++;
                  // Placed between the served events by time.
                  const forged = show(order, window, [forgedClaim(x.device, claimed, slot + 0.5)]);
                  if (!forged.noticed) {
                    note('MO-forged-number', [...describe(order, window, forged),
                      `=> an unsigned event claiming ${x.device} #${claimed} at slot ${slot} hides that ${x.name} was withheld`]);
                  }
                }
              }
            }
          }
          // MO-tail (limit): withholding what nothing served came after goes unnoticed.
          if (!withheldPast.length && withheldTail.length && !reordered && !noticed) {
            note('MO-tail', [...trace, `=> ${withheldTail.map((g) => g.name).join(', ')} withheld, and nothing could say so`]);
          }
          // MO-edit: the message shows the newest served edit of it, or says it cannot.
          const a1 = shown.find((m) => m.id === honestId.get('A1'));
          const newestEdit = order.filter((g) => g.type === 'edit' && g.refName === 'A1').sort((x, y) => y.seq - x.seq)[0];
          if (a1 && newestEdit && a1.content !== newestEdit.content && !noticed) {
            note('MO-edit', [...trace, `=> A1 shows "${a1.content}" although its edit ${newestEdit.name} was served, and nothing says so`]);
          }
          // MO-honest: everything, in the order written: nothing is noticed and the latest edit shows.
          if (order.length === genuine.length && order.every((g, i) => g === honestOrder[i])) {
            if (noticed || a1?.content !== byName.get('A4')!.content) note('MO-honest', [...trace, '=> an honest history is flagged or misshown']);
          }
        }
        if (window === 'suffix') {
          // MO-honest-suffix: the newest events of an honest history, as a page shows them, are not flagged.
          const isSuffix = honestRun && order.at(-1) === genuine.at(-1);
          if (isSuffix && noticed) note('MO-honest-suffix', [...trace, '=> the newest page of an honest history is flagged']);
          // MO-suffix (limit): in the newest page alone, a withheld event may pass for an older one.
          if (withheldPast.length && !reordered && !noticed) {
            note('MO-suffix', [...trace, `=> ${withheldPast.map((g) => g.name).join(', ')} withheld; the page cannot tell it from an older event`]);
          }
        }
        // MO-honest-forum: a forum's list serves a post with its latest edit
        // only (and posts in the order written): nothing is flagged and the
        // latest edit shows.
        if (window === 'forum' && order.map((g) => g.name).join() === 'A1,A4') {
          const a1 = shown.find((m) => m.id === honestId.get('A1'));
          if (noticed || a1?.content !== byName.get('A4')!.content) {
            note('MO-honest-forum', [...trace, '=> a forum list of a post and its latest edit is flagged or misshown']);
          }
        }
        // MO-forum (limit): posts loaded one by one cannot show a gap.
        if (window === 'forum' && withheldPast.length && !reordered && !noticed) {
          note('MO-forum', [...trace, `=> ${withheldPast.map((g) => g.name).join(', ')} withheld in a forum, and nothing says so`]);
        }
      }
    }
  }
}

process.stdout.write(JSON.stringify({ histories, results }));
