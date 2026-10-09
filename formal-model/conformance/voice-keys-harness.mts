// M8k: runs the real call key manager (packages/client/src/services/
// voice-frame-keys.ts) of three clients under a malicious server and explores
// every schedule within the bounds below, breadth-first, replaying each
// schedule from fresh clients.
//
// A and B are in the call; C joins and leaves. The server chooses when each
// pending step of each client finishes (a signature, the server's
// acknowledgement of a relayed message, the wait before using a key after a
// join), when and whether it delivers each key message to its target, whether
// it delivers one again, and when it tells A and B that C joined or left.
// Wrapping and signing are symbolic and unforgeable: a wrapped key opens only
// for its recipient device, and only the sender device signs. C is assumed to
// read every key message addressed to it, also after it left.
//
// Properties (checked on every state):
//   KJ  a key sent to C was made after its sender knew that C joined
//   KL  once a participant knew that C left, it neither sends C a key nor
//       starts sending under a key it ever sent to C
//   KR  a participant accepts each key of a sender at most once, never after a
//       newer one, and only as the key of the participant that made it
//   KH  once the server delivered everything, every two current participants
//       hold each other's current key (and the current keys differ from any
//       key C received, after C left)
//
// Two choices are left out because they cannot change what follows: which of
// a client's pending acknowledgements comes first (they all end the waits of
// one rotation), and delivering a message to C after it left (it stopped).
//
// States are compared by a SHA-256 digest of their fingerprint. With
// workers > 1, worker threads replay the schedules of each search depth and
// the main thread takes their results in the same order as a single thread.
//
// Input: { scenario: 'join' | 'join-leave', maxStates, duplicates, mutation, stop, progress, workers }
// Output: { executions, states, transitions, depth, complete, violations }
// With { scenario, schedule: [...] } it replays that one schedule and reports
// the choices, violations and fingerprint of the state it reaches.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';

const { VoiceFrameKeys } = await import('../../packages/client/src/services/voice-frame-keys.ts');
const { serializeVoiceKeyEnvelope } = await import('../../packages/shared/src/security/index.ts');

type Name = 'a' | 'b' | 'c';
interface Input {
  scenario: 'join' | 'join-leave';
  maxStates?: number;
  duplicates?: boolean;
  mutation?: 'pre-fix-rotation' | 'join-sends-current-key' | 'receive-without-replay-check';
  stop?: string[];
  /** Report each new search depth on stderr. */
  progress?: boolean;
  /** Worker threads that replay schedules (the search itself, and so its result, stays the same). */
  workers?: number;
  /** Replay this one schedule and report the state it reaches instead of searching. */
  schedule?: string[];
}

const input: Input = isMainThread ? JSON.parse(readFileSync(0, 'utf8')) : workerData;
const CHANNEL = '00000000-0000-4000-8000-0000000000c1';
const INDEX: Record<Name, number> = { a: 1, b: 2, c: 3 };
const peer = (name: Name) => ({ participantId: `p-${name}`, userId: `u-${name}`, deviceId: `d-${name}` });
const nameOf = (id: string) => id.slice(2) as Name;

interface Pending { label: string; resolve: () => void }
interface Message { label: string; from: Name; to: Name; keyId: number; envelope: any; signature: string; delivered: number }
interface Violation { property: string; message: string }

class World {
  pending: Pending[] = [];
  messages: Message[] = [];
  clients = new Map<Name, Client>();
  /** Every key: who made it and what it knew then. */
  keys = new Map<number, { creator: Name; knewJoin: boolean }>();
  violations: Violation[] = [];
  cJoined = false;
  cLeft = false;
  notified = new Set<string>();
}

const drain = async () => {
  // Everything between two choices runs in microtasks (wrapping, signing and
  // delivery are symbolic): after two turns of the event loop it has settled.
  for (let round = 0; round < 3; round += 1) await new Promise((resolve) => setImmediate(resolve));
};

class Client {
  readonly keys: InstanceType<typeof VoiceFrameKeys>;
  knowsJoin = false;
  knowsLeave = false;
  readonly installed: number[] = [];
  readonly received = new Map<Name, number[]>();
  private counters = { key: 0, sign: 0, ack: 0, delay: 0 };
  private lastKeyId = 0;

  constructor(private readonly world: World, readonly name: Name) {
    const self = { channelId: CHANNEL, ...peer(name) };
    const pending = (kind: 'sign' | 'ack' | 'delay', value: unknown) => new Promise<any>((resolve) => {
      world.pending.push({ label: `${kind}(${name}#${++this.counters[kind]})`, resolve: () => resolve(value) });
    });
    this.keys = new VoiceFrameKeys(self, {
      // Key ids are per client, so the same logical key has the same id in every schedule.
      randomKeyId: () => {
        this.lastKeyId = INDEX[name] * 1000 + ++this.counters.key;
        world.keys.set(this.lastKeyId, { creator: name, knewJoin: this.knowsJoin });
        return this.lastKeyId;
      },
      randomKey: () => keyBytes(this.lastKeyId),
      identities: async (deviceIds) => new Map(deviceIds.map((deviceId) => [deviceId, { userId: `u-${deviceId.slice(2)}`, identityKey: deviceId }])),
      wrapKey: async (key, identityKey) => wrap(identityKey, keyIdOf(key)),
      unwrapKey: async (wrapped) => {
        const opened = unwrap(wrapped);
        if (opened.recipient !== `d-${name}`) throw new Error('not for this device');
        return keyBytes(opened.keyId);
      },
      sign: (envelope) => pending('sign', `sig:${envelope.senderDeviceId}:${serializeVoiceKeyEnvelope(envelope)}`),
      verify: async (envelope, signature, identityKey) => (
        identityKey === envelope.senderDeviceId && signature === `sig:${envelope.senderDeviceId}:${serializeVoiceKeyEnvelope(envelope)}`
      ),
      send: (envelope, signature) => {
        const to = nameOf(envelope.targetParticipantId);
        const key = world.keys.get(envelope.keyId)!;
        if (to === 'c' && !key.knewJoin) {
          world.violations.push({ property: 'KJ', message: `${name} sends c key ${envelope.keyId}, made before ${name} knew that c joined` });
        }
        if (to === 'c' && this.knowsLeave) {
          world.violations.push({ property: 'KL', message: `${name} sends c key ${envelope.keyId} after it knew that c left` });
        }
        world.messages.push({ label: `${name}>${to}#${envelope.sequence}`, from: name, to, keyId: envelope.keyId, envelope, signature, delivered: 0 });
        return pending('ack', true);
      },
      useSendKey: async (keyId) => {
        this.installed.push(keyId);
        if (this.knowsLeave && world.messages.some((message) => message.from === name && message.to === 'c' && message.keyId === keyId)) {
          world.violations.push({ property: 'KL', message: `${name} starts sending under key ${keyId}, which it sent to c, after it knew that c left` });
        }
      },
      addReceiveKey: async (participantId, keyId) => {
        const from = nameOf(participantId);
        const earlier = this.received.get(from) ?? [];
        // A sender's keys are made, and sent to each participant, in increasing order.
        if (earlier.some((previous) => previous >= keyId)) {
          world.violations.push({ property: 'KR', message: `${name} accepts key ${keyId} of ${from} again or after a newer one` });
        }
        if (world.keys.get(keyId)?.creator !== from) {
          world.violations.push({ property: 'KR', message: `${name} accepts key ${keyId} as ${from}'s` });
        }
        this.received.set(from, [...earlier, keyId]);
      },
      removeReceiveKey: () => undefined,
      removeParticipant: () => undefined,
      delay: () => pending('delay', undefined),
    });
  }

  async deliver(message: Message): Promise<void> {
    await this.keys.receive(message.envelope, message.signature);
  }
}

function keyBytes(keyId: number): Uint8Array {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, keyId);
  return bytes;
}
const keyIdOf = (key: Uint8Array) => new DataView(key.buffer, key.byteOffset).getUint32(0);
const wrap = (recipient: string, keyId: number) => Buffer.from(JSON.stringify({ recipient, keyId }).padEnd(120, ' ')).toString('base64');
const unwrap = (wrapped: string) => JSON.parse(Buffer.from(wrapped, 'base64').toString().trim()) as { recipient: string; keyId: number };

// --- Controls: the real class with one step taken away ----------------------

function applyMutation(): void {
  const prototype = VoiceFrameKeys.prototype as any;
  if (input.mutation === 'pre-fix-rotation') {
    // Before 2026-10-09: no check right before sending, and a key that reached
    // someone who left meanwhile was still used.
    prototype.rotateNow = async function rotateNow(this: any, reason: string) {
      if (this.closed) return;
      const keyId = this.deps.randomKeyId();
      const key = this.deps.randomKey();
      this.ownKeyIds.add(keyId);
      this.keyOwners.set(keyId, this.self.participantId);
      const recipients = [...this.participants.values()];
      const identities = recipients.length ? await this.deps.identities(recipients.map((p: any) => p.deviceId)) : new Map();
      await Promise.allSettled(recipients.map(async (p: any) => {
        const identity = identities.get(p.deviceId);
        const sequence = (this.outboundSequences.get(p.participantId) ?? 0) + 1;
        this.outboundSequences.set(p.participantId, sequence);
        const envelope = {
          type: 'voice-key', sequence, channelId: this.self.channelId, senderParticipantId: this.self.participantId,
          senderDeviceId: this.self.deviceId, targetParticipantId: p.participantId, targetDeviceId: p.deviceId, keyId,
          wrappedKey: await this.deps.wrapKey(key, identity.identityKey),
        };
        if (this.closed || !this.participants.has(p.participantId)) return false;
        return this.deps.send(envelope, await this.deps.sign(envelope));
      }));
      if (this.closed) return;
      if (reason !== 'start' && recipients.length && this.currentKeyId !== null) await this.deps.delay(250);
      if (this.closed) return;
      await this.deps.useSendKey(keyId, key);
      this.currentKeyId = keyId;
    };
  } else if (input.mutation === 'join-sends-current-key') {
    // A newcomer gets the key in use instead of a new one.
    const rotate = prototype.rotateNow;
    prototype.rotateNow = async function rotateNow(this: any, reason: string) {
      if (reason !== 'join' || this.currentKeyId === null) return rotate.call(this, reason);
      const keyId = this.currentKeyId;
      const deps = this.deps;
      this.deps = { ...deps, randomKeyId: () => keyId, randomKey: () => keyBytes(keyId) };
      this.ownKeyIds.delete(keyId);
      this.keyOwners.delete(keyId);
      try {
        return await rotate.call(this, 'start');
      } finally {
        this.deps = deps;
      }
    };
  } else if (input.mutation === 'receive-without-replay-check') {
    const receive = prototype.receive;
    prototype.receive = async function receiveAgain(this: any, envelope: any, signature: string) {
      const state = this.inbound.get(envelope.senderParticipantId);
      if (state) {
        state.lastSequence = 0;
        state.keyIds = [];
      }
      if (this.keyOwners.get(envelope.keyId) === envelope.senderParticipantId) this.keyOwners.delete(envelope.keyId);
      return receive.call(this, envelope, signature);
    };
  } else if (input.mutation) {
    throw new Error(`unknown mutation ${input.mutation}`);
  }
}
applyMutation();

// --- One execution ------------------------------------------------------------

const others = (name: Name, world: World): Name[] => (['a', 'b', 'c'] as Name[]).filter((other) => (
  other !== name && world.clients.has(other) && !(other === 'c' && world.cLeft)
));

async function fresh(): Promise<World> {
  const world = new World();
  for (const name of ['a', 'b'] as Name[]) world.clients.set(name, new Client(world, name));
  // A and B are already in the call with each other's keys.
  for (const name of ['a', 'b'] as Name[]) void world.clients.get(name)!.keys.start([peer(name === 'a' ? 'b' : 'a')]);
  for (let guard = 0; guard < 100; guard += 1) {
    await drain();
    const next = world.pending.shift();
    if (next) {
      next.resolve();
      continue;
    }
    const message = world.messages.find((entry) => entry.delivered === 0);
    if (!message) break;
    message.delivered += 1;
    await world.clients.get(message.to)!.deliver(message);
  }
  await drain();
  world.messages = [];
  return world;
}

function choices(world: World): string[] {
  const out: string[] = [];
  const acking = new Set<string>();
  for (const entry of world.pending) {
    // A client's pending acknowledgements all belong to the one rotation it
    // runs, and each only ends the wait of its own send: which of them the
    // server answers first makes no difference, so only the oldest is offered.
    const ack = /^ack\((\w)#/.exec(entry.label);
    if (ack) {
      if (acking.has(ack[1]!)) continue;
      acking.add(ack[1]!);
    }
    out.push(`resolve ${entry.label}`);
  }
  for (const message of world.messages) {
    // C stopped (close) when it left; a message delivered to it then changes nothing.
    if (message.to === 'c' && world.cLeft) continue;
    if (message.delivered === 0 || (input.duplicates && message.delivered === 1)) out.push(`deliver ${message.label}`);
  }
  if (!world.cJoined) out.push('c joins');
  for (const name of ['a', 'b'] as Name[]) {
    if (world.cJoined && !world.notified.has(`join ${name}`)) out.push(`tell ${name} that c joined`);
  }
  if (input.scenario === 'join-leave') {
    if (world.cJoined && !world.cLeft) out.push('c leaves');
    for (const name of ['a', 'b'] as Name[]) {
      if (world.cLeft && world.notified.has(`join ${name}`) && !world.notified.has(`leave ${name}`)) out.push(`tell ${name} that c left`);
    }
  }
  return out;
}

async function apply(world: World, choice: string): Promise<void> {
  if (choice.startsWith('resolve ')) {
    const index = world.pending.findIndex((entry) => entry.label === choice.slice(8));
    const [entry] = world.pending.splice(index, 1);
    entry!.resolve();
  } else if (choice.startsWith('deliver ')) {
    const message = world.messages.find((entry) => entry.label === choice.slice(8))!;
    message.delivered += 1;
    const target = world.clients.get(message.to);
    if (target) await target.deliver(message);
  } else if (choice === 'c joins') {
    world.cJoined = true;
    const c = new Client(world, 'c');
    c.knowsJoin = true;
    world.clients.set('c', c);
    void c.keys.start([peer('a'), peer('b')]);
  } else if (choice.startsWith('tell ')) {
    const name = choice[5] as Name;
    const client = world.clients.get(name)!;
    if (choice.endsWith('joined')) {
      world.notified.add(`join ${name}`);
      client.knowsJoin = true;
      void client.keys.participantJoined(others(name, world).map(peer)).catch(() => undefined);
    } else {
      world.notified.add(`leave ${name}`);
      client.knowsLeave = true;
      void client.keys.participantLeft('p-c', others(name, world).map(peer)).catch(() => undefined);
    }
  } else if (choice === 'c leaves') {
    world.cLeft = true;
    world.clients.get('c')!.keys.close();
  }
  await drain();
}

function check(world: World): Violation[] {
  const out = [...world.violations];
  // KH: once the server delivered everything, current participants hold each other's current keys.
  const caughtUp = world.pending.length === 0
    && world.messages.every((message) => message.delivered > 0 || (message.to === 'c' && world.cLeft))
    && (!world.cJoined || (world.notified.has('join a') && world.notified.has('join b')))
    && (!world.cLeft || (world.notified.has('leave a') && world.notified.has('leave b')));
  if (caughtUp) {
    const current = (['a', 'b', 'c'] as Name[]).filter((name) => world.clients.has(name) && !(name === 'c' && world.cLeft));
    for (const sender of current) {
      const keyId = world.clients.get(sender)!.keys.currentKeyId;
      if (keyId === null) {
        out.push({ property: 'KH', message: `${sender} sends under no key` });
        continue;
      }
      for (const receiver of current) {
        if (receiver !== sender && !(world.clients.get(receiver)!.received.get(sender) ?? []).includes(keyId)) {
          out.push({ property: 'KH', message: `${receiver} lacks ${sender}'s current key ${keyId}` });
        }
      }
      if (world.cLeft && world.messages.some((message) => message.to === 'c' && message.keyId === keyId)) {
        out.push({ property: 'KH', message: `${sender} still sends under key ${keyId}, which c received` });
      }
    }
  }
  return out;
}

/**
 * Everything that decides what can happen next, and what the checks see:
 * also the violations a step recorded (two schedules can reach the same
 * clients, one of them through a violation) and each key's origin.
 */
function fingerprint(world: World): string {
  const clients = [...world.clients.entries()].sort().map(([name, client]) => {
    const keys = client.keys as any;
    const own = client as any;
    return [
      name, client.knowsJoin, client.knowsLeave, client.installed, [...client.received.entries()].sort(),
      own.counters, own.lastKeyId,
      keys.early.map((message: any) => `${message.envelope.senderParticipantId}#${message.envelope.sequence}`),
      [...keys.participants.keys()].sort(), [...keys.inbound.entries()].map(([id, state]: [string, any]) => [id, state.lastSequence, state.keyIds]).sort(),
      [...keys.outboundSequences.entries()].sort(),
      [...keys.keyOwners.entries()].sort(), [...keys.ownKeyIds].sort(), keys.currentKeyId, keys.closed,
    ];
  });
  return JSON.stringify([
    clients,
    world.pending.map((entry) => entry.label).sort(),
    world.messages.map((message) => [message.label, message.keyId, message.delivered]).sort(),
    world.cJoined, world.cLeft, [...world.notified].sort(),
    [...world.keys.entries()].sort(), world.violations.map((violation) => `${violation.property} ${violation.message}`).sort(),
  ]);
}

async function replay(schedule: string[]): Promise<World> {
  const world = await fresh();
  for (const choice of schedule) await apply(world, choice);
  return world;
}

interface Child { choice: string; key: string; hits: Violation[] }
interface Expanded { children: Child[][]; executions: number }

const digest = (world: World) => createHash('sha256').update(fingerprint(world)).digest('base64');

/** Each schedule's choices, with the state each choice leads to. */
async function expand(schedules: string[][]): Promise<Expanded> {
  const children: Child[][] = [];
  let executions = 0;
  for (const schedule of schedules) {
    const parent = await replay(schedule);
    executions++;
    const options = choices(parent);
    const out: Child[] = [];
    for (const [index, choice] of options.entries()) {
      // The last choice continues the parent's own execution.
      let world = parent;
      if (index < options.length - 1) {
        world = await replay(schedule);
        executions++;
      }
      await apply(world, choice);
      out.push({ choice, key: digest(world), hits: check(world) });
    }
    children.push(out);
  }
  return { children, executions };
}

if (!isMainThread) {
  parentPort!.on('message', (schedules: string[][]) => {
    void expand(schedules).then((result) => parentPort!.postMessage(result));
  });
} else if (input.schedule) {
  const world = await replay(input.schedule);
  process.stdout.write(JSON.stringify({ choices: choices(world), violations: check(world), fingerprint: JSON.parse(fingerprint(world)) }));
} else {
  const workerCount = Math.max(1, Math.min(input.workers ?? 1, availableParallelism()));
  const pool = workerCount > 1
    ? Array.from({ length: workerCount }, () => new Worker(new URL(import.meta.url), { workerData: input }))
    : [];
  const seen = new Set<string>([digest(await replay([]))]);
  let level: string[][] = [[]];
  let executions = 1;
  let transitions = 0;
  let depth = 0;
  const violations: Array<Violation & { trace: string[] }> = [];
  const found = new Set<string>();
  const maxStates = input.maxStates ?? 500_000;
  const began = Date.now();
  const stopped = () => Boolean(input.stop?.length && input.stop.every((property) => found.has(property)));
  const halted = () => seen.size >= maxStates || stopped();

  /** The parents of one depth, in order; returns false if the search stopped before the last. */
  const searchLevel = (parents: string[][], next: string[][]) => new Promise<boolean>((resolve, reject) => {
    const size = Math.max(1, Math.min(64, Math.ceil(parents.length / (workerCount * 4))));
    const chunks: string[][][] = [];
    for (let index = 0; index < parents.length; index += size) chunks.push(parents.slice(index, index + size));
    const results: Array<Expanded | undefined> = [];
    let dispatched = 0;
    let taken = 0;
    let running = 0;
    let stop = false;
    const take = () => {
      while (!stop && taken < chunks.length && results[taken]) {
        const chunk = chunks[taken]!;
        const { children, executions: runs } = results[taken]!;
        results[taken] = undefined;
        executions += runs;
        for (const [index, schedule] of chunk.entries()) {
          for (const child of children[index]!) {
            transitions++;
            if (seen.has(child.key)) continue;
            seen.add(child.key);
            const trace = [...schedule, child.choice];
            for (const hit of child.hits) {
              if (found.has(hit.property)) continue;
              found.add(hit.property);
              violations.push({ ...hit, trace });
            }
            if (!child.hits.length) next.push(trace);
          }
        }
        taken++;
        if (halted()) stop = true;
      }
      if (taken === chunks.length) resolve(true);
      else if (stop && running === 0) resolve(false);
    };
    const feed = (run: (chunk: string[][]) => Promise<Expanded>) => {
      if (stop || dispatched >= chunks.length) return;
      const id = dispatched++;
      running++;
      run(chunks[id]!).then((result) => {
        running--;
        results[id] = result;
        take();
        feed(run);
      }, reject);
    };
    if (!chunks.length) return resolve(true);
    if (!pool.length) feed(expand);
    for (const worker of pool) {
      feed((chunk) => new Promise<Expanded>((done, fail) => {
        worker.once('message', done);
        worker.once('error', fail);
        worker.postMessage(chunk);
      }).finally(() => worker.removeAllListeners('error')));
    }
  });

  let finished = true;
  while (level.length) {
    depth = level[0]!.length;
    if (input.progress) process.stderr.write(`depth ${depth}: ${seen.size} states, ${level.length} to expand, ${Math.round((Date.now() - began) / 1000)}s\n`);
    const next: string[][] = [];
    if (!await searchLevel(level, next)) {
      finished = false;
      break;
    }
    level = next;
  }
  await Promise.all(pool.map((worker) => worker.terminate()));
  process.stdout.write(JSON.stringify({
    executions, states: seen.size, transitions, depth, complete: finished || stopped(), violations,
  }));
}
