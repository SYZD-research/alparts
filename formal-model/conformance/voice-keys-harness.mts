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
//   KT  a delivered key message waits only for its own install or for an
//       earlier message of the same sender, never for the receiver's own
//       rotation (which waits for the server)
//   KW  once a client's key messages settled, its frame worker holds exactly
//       the keys the client keeps for each current sender, and none of a
//       sender it forgot
//
// Options widen what the server and the participants can do: with
// installSteps, B's frame worker installs each key (or, with 'c', each of C's
// keys) when the server's schedule says so (so B handles several messages at
// once); with insider, C also signs key messages of its own making for B
// (three new key ids, then its first key id again, each once the call has
// settled); with failAck, the server may fail to relay one key message (its
// sender then sends a new key again).
//
// Two choices are left out because they cannot change what follows: which of
// a client's pending acknowledgements comes first (they all end the waits of
// one rotation), and delivering a message to C after it left (it stopped).
//
// States are compared by a SHA-256 digest of their fingerprint. With
// workers > 1, worker threads replay the schedules of each search depth and
// the main thread takes their results in the same order as a single thread.
//
// Input: { scenario: 'join' | 'join-leave', maxStates, duplicates, installSteps, insider, failAck, mutation, stop,
//          progress, workers }
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
  /** B's frame worker installs keys when the server's schedule says so: all of them, or only C's ('c'). */
  installSteps?: boolean | 'c';
  insider?: boolean;
  failAck?: boolean;
  mutation?: 'pre-fix-rotation' | 'join-sends-current-key' | 'receive-without-replay-check'
    | 'shared-receive-queue' | 'unserialized-receive' | 'install-after-leave' | 'no-retry';
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

interface Pending { label: string; resolve: (value?: unknown) => void; message?: Message }
/** delivered: times delivered, or -1 when the server failed to relay it. */
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
  failed = false;
  forged = 0;
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
  /** The frame worker's receive keys and their senders. */
  readonly worker = new Map<number, Name>();
  /** Delivered key messages whose handling has not settled, oldest first. */
  readonly inflight: Message[] = [];
  private counters = { key: 0, sign: 0, ack: 0, delay: 0, install: 0 };
  private lastKeyId = 0;

  constructor(private readonly world: World, readonly name: Name) {
    const self = { channelId: CHANNEL, ...peer(name) };
    const pending = (kind: 'sign' | 'ack' | 'delay' | 'install', value: unknown, message?: Message, note = '') => new Promise<any>((resolve) => {
      world.pending.push({
        label: `${kind}(${name}#${++this.counters[kind]}${note})`,
        resolve: (override?: unknown) => resolve(override === undefined ? value : override),
        message,
      });
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
        const message = { label: `${name}>${to}#${envelope.sequence}`, from: name, to, keyId: envelope.keyId, envelope, signature, delivered: 0 };
        world.messages.push(message);
        return pending('ack', true, message);
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
        // The frame worker installs asynchronously; with installSteps the server's schedule decides when, at B.
        if (name === 'b' && (input.installSteps === true || (input.installSteps === 'c' && from === 'c'))) {
          await pending('install', undefined, undefined, `:${from}:${keyId}`);
        }
        this.worker.set(keyId, from);
      },
      removeReceiveKey: (keyId) => {
        this.worker.delete(keyId);
      },
      removeParticipant: (participantId) => {
        for (const [keyId, sender] of [...this.worker]) if (sender === nameOf(participantId)) this.worker.delete(keyId);
      },
      delay: () => pending('delay', undefined),
    });
  }

  /** Hands the message to the key manager without waiting for it to settle. */
  deliver(message: Message): void {
    this.inflight.push(message);
    void this.keys.receive(message.envelope, message.signature).catch(() => false).then(() => {
      this.inflight.splice(this.inflight.indexOf(message), 1);
    });
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
  } else if (input.mutation === 'shared-receive-queue') {
    // 0eda053..a75ca5c: every key message waited on the queue of this participant's own rotations.
    prototype.receive = function receive(this: any, envelope: any, signature: string) {
      const run = this.queue.catch(() => undefined).then(() => this.receiveNow(envelope, signature));
      this.queue = run.then(() => undefined, () => undefined);
      return run;
    };
  } else if (input.mutation === 'unserialized-receive') {
    // Before 0eda053: receive ran unserialized, counted the sequence before its
    // awaits and accepted a key id again once it had left the kept keys.
    prototype.receive = async function receive(this: any, envelope: any, signature: string) {
      if (this.closed) return false;
      if (envelope.targetParticipantId !== this.self.participantId || envelope.senderParticipantId === this.self.participantId) return false;
      const sender = this.participants.get(envelope.senderParticipantId);
      if (!sender) {
        this.early.push({ envelope, signature });
        if (this.early.length > 16) this.early.shift();
        return false;
      }
      if (sender.deviceId !== envelope.senderDeviceId) return false;
      const identity = (await this.deps.identities([sender.deviceId]).catch(() => null))?.get(sender.deviceId);
      if (!identity || identity.userId !== sender.userId) return false;
      if (!await this.deps.verify(envelope, signature, identity.identityKey).catch(() => false)) return false;
      if (this.closed || this.participants.get(sender.participantId) !== sender) return false;
      const state = this.inbound.get(sender.participantId) ?? { deviceId: sender.deviceId, lastSequence: 0, keyIds: [] };
      if (state.deviceId !== sender.deviceId || envelope.sequence <= state.lastSequence) return false;
      const owner = this.keyOwners.get(envelope.keyId);
      if (owner !== undefined && (owner !== sender.participantId || state.keyIds.includes(envelope.keyId))) return false;
      state.lastSequence = envelope.sequence;
      this.inbound.set(sender.participantId, state);
      let key: Uint8Array;
      try {
        key = await this.deps.unwrapKey(envelope.wrappedKey);
      } catch {
        return false;
      }
      if (key.length !== 32 || this.closed || this.participants.get(sender.participantId) !== sender) return false;
      if (this.keyOwners.has(envelope.keyId) && this.keyOwners.get(envelope.keyId) !== sender.participantId) return false;
      this.keyOwners.set(envelope.keyId, sender.participantId);
      state.keyIds.push(envelope.keyId);
      await this.deps.addReceiveKey(sender.participantId, envelope.keyId, key);
      key.fill(0);
      while (state.keyIds.length > 3) this.deps.removeReceiveKey(state.keyIds.shift()!);
      return true;
    };
  } else if (input.mutation === 'install-after-leave') {
    // 0eda053..a75ca5c (the checks and the install, without the queue): no
    // check after the install, so the key of a sender who left while it was
    // installed stayed in the frame worker and its sequence state came back.
    prototype.receiveNow = async function receiveNow(this: any, envelope: any, signature: string) {
      if (this.closed) return false;
      if (envelope.targetParticipantId !== this.self.participantId || envelope.senderParticipantId === this.self.participantId) return false;
      const sender = this.participants.get(envelope.senderParticipantId);
      if (!sender) {
        this.early.push({ envelope, signature });
        if (this.early.length > 16) this.early.shift();
        return false;
      }
      if (sender.deviceId !== envelope.senderDeviceId) return false;
      const identity = (await this.deps.identities([sender.deviceId]).catch(() => null))?.get(sender.deviceId);
      if (!identity || identity.userId !== sender.userId) return false;
      if (!await this.deps.verify(envelope, signature, identity.identityKey).catch(() => false)) return false;
      if (this.closed || this.participants.get(sender.participantId) !== sender) return false;
      const state = this.inbound.get(sender.participantId) ?? { deviceId: sender.deviceId, lastSequence: 0, keyIds: [] };
      if (state.deviceId !== sender.deviceId || envelope.sequence <= state.lastSequence) return false;
      if (this.keyOwners.has(envelope.keyId)) return false;
      let key: Uint8Array;
      try {
        key = await this.deps.unwrapKey(envelope.wrappedKey);
      } catch {
        return false;
      }
      if (key.length !== 32 || this.closed || this.participants.get(sender.participantId) !== sender) return false;
      this.keyOwners.set(envelope.keyId, sender.participantId);
      state.keyIds.push(envelope.keyId);
      try {
        await this.deps.addReceiveKey(sender.participantId, envelope.keyId, key);
      } finally {
        key.fill(0);
      }
      state.lastSequence = envelope.sequence;
      this.inbound.set(sender.participantId, state);
      while (state.keyIds.length > 3) this.deps.removeReceiveKey(state.keyIds.shift()!);
      return true;
    };
  } else if (input.mutation === 'no-retry') {
    // Before d3319e3: a key that did not reach everyone was not sent again.
    prototype.retryLater = function retryLater() {};
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
    world.clients.get(message.to)!.deliver(message);
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
  if (input.failAck && !world.failed) {
    // Only a message the server has not delivered yet can be reported as not relayed.
    for (const entry of world.pending) if (entry.label.startsWith('ack(') && entry.message!.delivered === 0) out.push(`fail ${entry.label}`);
  }
  // C signs three key messages of its own with new key ids, enough to push its
  // first key out of the three B keeps, and then one naming that first key again.
  // It does so once the call has settled (nothing pending, everything delivered),
  // which keeps the search small and is all the key id checks need.
  const settled = world.pending.length === 0 && world.messages.every((message) => message.delivered !== 0);
  if (input.insider && settled && world.cJoined && !world.cLeft && world.forged < 4 && world.keys.has(3001)) {
    out.push(`c forges key ${world.forged < 3 ? 3101 + world.forged : 3001} for b`);
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
  } else if (choice.startsWith('fail ')) {
    // The server did not relay this message and says so.
    const index = world.pending.findIndex((entry) => entry.label === choice.slice(5));
    const [entry] = world.pending.splice(index, 1);
    world.failed = true;
    entry!.message!.delivered = -1;
    entry!.resolve(false);
  } else if (choice.startsWith('c forges key ')) {
    // C signs, with its own device, a key message of its own making for B.
    const keyId = Number(choice.split(' ')[3]);
    const keys = world.clients.get('c')!.keys as any;
    const sequence = (keys.outboundSequences.get('p-b') ?? 0) + 1;
    keys.outboundSequences.set('p-b', sequence);
    const envelope = {
      type: 'voice-key', sequence, channelId: CHANNEL, senderParticipantId: 'p-c', senderDeviceId: 'd-c',
      targetParticipantId: 'p-b', targetDeviceId: 'd-b', keyId, wrappedKey: wrap('d-b', keyId),
    };
    if (!world.keys.has(keyId)) world.keys.set(keyId, { creator: 'c', knewJoin: true });
    world.forged += 1;
    world.messages.push({ label: `c!b#${sequence}`, from: 'c', to: 'b', keyId, envelope,
      signature: `sig:d-c:${serializeVoiceKeyEnvelope(envelope as any)}`, delivered: 0 });
  } else if (choice.startsWith('deliver ')) {
    const message = world.messages.find((entry) => entry.label === choice.slice(8))!;
    message.delivered += 1;
    const target = world.clients.get(message.to);
    if (target) target.deliver(message);
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
    && world.messages.every((message) => message.delivered !== 0 || (message.to === 'c' && world.cLeft))
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
  for (const [name, client] of world.clients) {
    const keys = client.keys as any;
    if (keys.closed) continue;
    // KT: each message still being handled waits for its own install or an earlier message of its sender.
    for (const [index, message] of client.inflight.entries()) {
      const installing = world.pending.some((entry) => entry.label.startsWith(`install(${name}#`)
        && entry.label.endsWith(`:${message.from}:${message.keyId})`));
      const queued = client.inflight.slice(0, index).some((earlier) => earlier.from === message.from);
      if (!installing && !queued) {
        out.push({ property: 'KT', message: `${name}'s handling of ${message.label} waits for neither its install nor an earlier message of ${message.from}` });
      }
    }
    // KW: once nothing is being handled, the frame worker holds what the client keeps.
    const installs = world.pending.some((entry) => entry.label.startsWith(`install(${name}#`));
    if (client.inflight.length || installs) continue;
    const kept = new Map<number, Name>();
    for (const [participantId, state] of keys.inbound as Map<string, { keyIds: number[] }>) {
      for (const keyId of state.keyIds) kept.set(keyId, nameOf(participantId));
    }
    for (const [keyId, sender] of [...client.worker, ...kept]) {
      if (!keys.participants.has(`p-${sender}`)) {
        out.push({ property: 'KW', message: `${name} still holds key ${keyId} of ${sender}, which it forgot` });
      }
    }
    for (const [keyId, sender] of client.worker) {
      if (kept.get(keyId) !== sender) {
        out.push({ property: 'KW', message: `${name}'s frame worker holds key ${keyId} of ${sender}, which ${name} no longer keeps` });
      }
    }
    for (const [keyId, sender] of kept) {
      if (client.worker.get(keyId) !== sender) out.push({ property: 'KW', message: `${name} keeps key ${keyId} of ${sender} that its frame worker lacks` });
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
      [...client.worker.entries()].sort(), client.inflight.map((message) => message.label),
      [...keys.receiving.keys()].sort(), keys.rotations, keys.retries,
    ];
  });
  return JSON.stringify([
    clients,
    world.pending.map((entry) => entry.label).sort(),
    world.messages.map((message) => [message.label, message.keyId, message.delivered]).sort(),
    world.cJoined, world.cLeft, [...world.notified].sort(), world.failed, world.forged,
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
