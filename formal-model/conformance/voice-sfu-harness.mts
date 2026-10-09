// Runs the real SFU coordinator (packages/server/src/voice) against a scripted
// stand-in for mediasoup and explores every interleaving of coordinator calls
// and of the resolution (or failure) of each mediasoup request, breadth-first,
// within the bounds given on stdin. A schedule is replayed from a fresh
// coordinator; states are deduplicated by a fingerprint of every coordinator
// map, every stand-in object and every unsettled call and request.
//
// The stand-in follows mediasoup 3.x where it matters here: close() of a
// router or transport closes its transports, producers and consumers
// synchronously and emits observer 'close'; consumers of a closed producer are
// closed later by a worker notification ('producerclose'); requests made on a
// closed object fail.
//
// Input: { maxOps, maxJoins, channels, workers, failures, ops, mutation, scenario }
// Output: { executions, states, transitions, violations: [{ property, message, trace }] }
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';

const { VoiceCoordinator } = await import('../../packages/server/src/voice/voice-coordinator.ts');

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

interface Input {
  maxOps: number;
  maxJoins: number;
  channels: string[];
  workers: number;
  failures: boolean;
  ops: string[];
  mutation?: string;
  scenario?: string;
  maxStates?: number;
  /** Stop once all of these properties were violated (controls). */
  stop?: string[];
}

const input: Input = JSON.parse(readFileSync(0, 'utf8'));
const CHANNEL_UUID: Record<string, string> = {
  X: '00000000-0000-4000-8000-00000000000a',
  Y: '00000000-0000-4000-8000-00000000000b',
};
const RTP_PARAMETERS = { codecs: [], encodings: [], headerExtensions: [], rtcp: {} };
const RTP_CAPABILITIES = { codecs: [], headerExtensions: [] };
const DTLS = { role: 'client', fingerprints: [] };

// ---------------------------------------------------------------------------
// The stand-in
// ---------------------------------------------------------------------------

interface Pending {
  label: string;
  worker: FakeWorker | null;
  settle: (fail: boolean) => void;
}

class World {
  next = 1;
  objects: Fake[] = [];
  /** Created in the worker, not yet answered to Node. */
  workerSide = new Set<Fake>();
  pending: Pending[] = [];

  id(prefix: string): string {
    return `${prefix}${this.next++}`;
  }

  request<T>(label: string, run: () => T, worker: FakeWorker | null = null, onFail?: () => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const entry: Pending = {
        label,
        worker,
        settle: (fail) => {
          this.pending.splice(this.pending.indexOf(entry), 1);
          if (fail) {
            onFail?.();
            reject(new Error(`FAKE_FAILURE ${label}`));
            return;
          }
          try {
            resolve(run());
          } catch (error) {
            reject(error);
          }
        },
      };
      this.pending.push(entry);
    });
  }
}

abstract class Fake {
  /** Node-side flag, as mediasoup's `closed`. */
  closed = false;
  /** Worker side: the object exists in the worker and forwards media. */
  alive = true;
  readonly observer = new EventEmitter();
  constructor(readonly world: World, readonly id: string, readonly type: string) {
    world.objects.push(this);
  }
  protected markClosed(): boolean {
    this.alive = false;
    if (this.closed) return false;
    this.closed = true;
    this.observer.emit('close');
    return true;
  }
}

/**
 * A request to the worker is processed in order: its effect happens when it
 * is sent, and only the answer to Node is delivered later. An object created
 * by a request sent before its parent was closed is answered as created and
 * appears open on the Node side, but the worker already destroyed it.
 */
function workerCreates<T extends Fake>(world: World, label: string, parentsAlive: () => boolean, create: () => T,
  worker: FakeWorker): Promise<T> {
  const ok = parentsAlive();
  const created = ok ? create() : null;
  if (created) {
    world.objects.splice(world.objects.indexOf(created), 1);   // not visible to Node until answered
    world.workerSide.add(created);
  }
  return world.request(label, () => {
    if (!created) throw new Error(`${label} failed in the worker`);
    world.workerSide.delete(created);
    world.objects.push(created);
    return created;
  }, worker, () => {
    // Never answered: the worker destroyed it, Node never saw it.
    if (created) {
      created.alive = false;
      world.workerSide.delete(created);
    }
  });
}

class FakeWorker extends Fake {
  routers: FakeRouter[] = [];
  servers: FakeServer[] = [];
  constructor(world: World) { super(world, world.id('w'), 'worker'); }
  get pid() { return 0; }
  on() { return this; }
  createWebRtcServer(_options: unknown): Promise<FakeServer> {
    return this.world.request(`webrtc-server@${this.id}`, () => {
      if (this.closed) throw new Error('worker closed');
      const server = new FakeServer(this.world, this);
      this.servers.push(server);
      return server;
    }, this);
  }
  createRouter(_options: unknown): Promise<FakeRouter> {
    return this.world.request(`router@${this.id}`, () => {
      if (this.closed) throw new Error('worker closed');
      const router = new FakeRouter(this.world, this);
      this.routers.push(router);
      return router;
    }, this);
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.alive = false;
    for (const router of this.routers) router.close();
    for (const server of this.servers) server.close();
    // Closing a worker closes its channel: every request still waiting fails.
    for (const entry of this.world.pending.filter((p) => p.worker === this)) entry.settle(true);
    this.observer.emit('close');
  }
}

class FakeServer extends Fake {
  transports: FakeTransport[] = [];
  constructor(world: World, readonly worker: FakeWorker) { super(world, world.id('s'), 'server'); }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.alive = false;
    for (const transport of this.transports) transport.close();
    this.observer.emit('close');
  }
}

class FakeRouter extends Fake {
  transports: FakeTransport[] = [];
  readonly rtpCapabilities = RTP_CAPABILITIES;
  constructor(world: World, readonly worker: FakeWorker) { super(world, world.id('r'), 'router'); }
  canConsume({ producerId }: { producerId: string }): boolean {
    return this.world.objects.some((o) => o instanceof FakeProducer && o.id === producerId && !o.closed
      && o.transport.router === this);
  }
  createWebRtcTransport(options: { webRtcServer: FakeServer; appData: Record<string, unknown> }): Promise<FakeTransport> {
    return workerCreates(this.world, `transport@${this.id}:${String(options.appData.participantId)}:${String(options.appData.direction)}`,
      () => this.alive && options.webRtcServer.alive, () => {
        const transport = new FakeTransport(this.world, this, options.webRtcServer, options.appData);
        this.transports.push(transport);
        options.webRtcServer.transports.push(transport);
        return transport;
      }, this.worker);
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.alive = false;
    for (const transport of this.transports) transport.close();
    this.observer.emit('close');
  }
}

class FakeTransport extends Fake {
  producers: FakeProducer[] = [];
  consumers: FakeConsumer[] = [];
  connected = false;
  readonly iceParameters = {};
  readonly iceCandidates = [];
  readonly dtlsParameters = DTLS;
  constructor(world: World, readonly router: FakeRouter, readonly server: FakeServer, readonly appData: Record<string, unknown>) {
    super(world, world.id('t'), 'transport');
  }
  connect(_options: unknown): Promise<void> {
    const ok = this.alive;
    if (ok) this.connected = true;
    return this.world.request(`connect@${this.id}`, () => {
      if (!ok) throw new Error('transport closed');
    }, this.router.worker);
  }
  produce(options: { appData: Record<string, unknown> }): Promise<FakeProducer> {
    return workerCreates(this.world, `produce@${this.id}`, () => this.alive, () => {
      const producer = new FakeProducer(this.world, this, options.appData);
      this.producers.push(producer);
      return producer;
    }, this.router.worker);
  }
  consume(options: { producerId: string; paused: boolean; appData: Record<string, unknown> }): Promise<FakeConsumer> {
    const producer = [...this.world.objects, ...this.world.workerSide].find((o): o is FakeProducer => o instanceof FakeProducer && o.id === options.producerId);
    return workerCreates(this.world, `consume@${this.id}:${options.producerId}`,
      () => this.alive && Boolean(producer?.alive) && producer!.transport.router === this.router, () => {
        const consumer = new FakeConsumer(this.world, this, producer!, options.paused, options.appData);
        this.consumers.push(consumer);
        producer!.consumers.push(consumer);
        return consumer;
      }, this.router.worker);
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.alive = false;
    // Node closes the producers and consumers it knows; the worker destroys all of them.
    for (const producer of this.producers) producer.workerOrNodeClose(this.world.objects.includes(producer));
    for (const consumer of this.consumers) consumer.workerOrNodeClose(this.world.objects.includes(consumer));
    this.observer.emit('close');
  }
}

class FakeProducer extends Fake {
  consumers: FakeConsumer[] = [];
  readonly kind = 'audio';
  constructor(world: World, readonly transport: FakeTransport, readonly appData: Record<string, unknown>) {
    super(world, world.id('p'), 'producer');
  }
  close() {
    if (!this.markClosed()) return;
    this.closeConsumersInWorker();
  }
  /** Closed with its transport: by Node when Node knows it, otherwise only in the worker. */
  workerOrNodeClose(known: boolean) {
    if (known) {
      this.close();
      return;
    }
    this.alive = false;
    this.closeConsumersInWorker();
  }
  private closeConsumersInWorker() {
    for (const consumer of this.consumers) {
      if (consumer.alive) {
        consumer.alive = false;
        // The worker tells Node later ('producerclose'), for consumers Node knows.
        void this.world.request(`producerclose@${consumer.id}`, () => {
          if (this.world.objects.includes(consumer)) consumer.close();
        }, this.transport.router.worker).catch(() => undefined);
      }
    }
  }
}

class FakeConsumer extends Fake {
  readonly kind = 'audio';
  readonly rtpParameters = RTP_PARAMETERS;
  constructor(world: World, readonly transport: FakeTransport, readonly producer: FakeProducer,
    public paused: boolean, readonly appData: Record<string, unknown>) {
    super(world, world.id('c'), 'consumer');
  }
  get producerId() { return this.producer.id; }
  resume(): Promise<void> {
    const ok = this.alive;
    if (ok) this.paused = false;
    return this.world.request(`resume@${this.id}`, () => {
      if (!ok) throw new Error('consumer closed');
    }, this.transport.router.worker);
  }
  close() { this.markClosed(); }
  workerOrNodeClose(known: boolean) {
    if (known) this.close();
    else this.alive = false;
  }
}

// ---------------------------------------------------------------------------
// One execution
// ---------------------------------------------------------------------------

interface Call {
  label: string;
  settled: boolean;
  outcome?: string;
}

interface Execution {
  world: World;
  coordinator: any;
  calls: Call[];
  participants: Array<{ id: string; channel: string }>;
  transportIds: Map<string, string>;
  consumerIds: Map<string, string[]>;
  started: number;
  joins: number;
  closeCalled: boolean;
  closeSettled: boolean;
  violations: Array<{ property: string; message: string }>;
}

const drain = () => new Promise<void>((resolve) => setImmediate(resolve));

async function fresh(): Promise<Execution> {
  const world = new World();
  const coordinator: any = new VoiceCoordinator({
    bindAddress: '127.0.0.1', announcedAddress: '127.0.0.1', basePort: 40000, workerCount: input.workers,
  });
  const workers = coordinator.workers;
  workers.start = async (count: number) => {
    for (let i = 0; i < count; i++) workers.workers.push(new FakeWorker(world));
  };
  applyMutation(coordinator);
  await coordinator.start();
  await drain();
  return {
    world, coordinator, calls: [], participants: [], transportIds: new Map(), consumerIds: new Map(),
    started: 0, joins: 0, closeCalled: false, closeSettled: false, violations: [],
  };
}

function applyMutation(coordinator: any): void {
  switch (input.mutation) {
    case undefined:
      return;
    case 'leave-keeps-transports':
      coordinator.transports.closeParticipant = () => undefined;
      return;
    case 'empty-channel-keeps-router':
      coordinator.routers.closeChannel = () => undefined;
      return;
    case 'consumer-without-recheck': {
      const consumers = coordinator.consumers;
      consumers.createConsumer = async (channelId: string, participantId: string, sourceParticipantId: string) => {
        const transport = consumers.transports.getTransport(participantId, 'recv');
        const producer = consumers.producers.getProducer(channelId, sourceParticipantId);
        if (!transport || !producer) throw new Error('VOICE_CONSUMER_PREREQUISITE');
        const consumer = await transport.consume({ producerId: producer.id, rtpCapabilities: RTP_CAPABILITIES, paused: true,
          appData: { channelId, participantId, sourceParticipantId } });
        const channel = consumers.channels.get(channelId) ?? new Map();
        const state = channel.get(participantId) ?? { consumers: new Map(), pending: new Map() };
        state.consumers.set(sourceParticipantId, consumer);
        channel.set(participantId, state);
        consumers.channels.set(channelId, channel);
        return consumer;
      };
      return;
    }
    case 'producer-without-reservation': {
      const producers = coordinator.producers;
      producers.createProducer = async (channelId: string, participantId: string, rtpParameters: unknown) => {
        const transport = producers.transports.getTransport(participantId, 'send');
        if (!transport) throw new Error('VOICE_SEND_TRANSPORT_NOT_FOUND');
        let state = producers.channels.get(channelId);
        if (!state) {
          state = { producers: new Map(), pending: new Map() };
          producers.channels.set(channelId, state);
        }
        if (state.producers.has(participantId)) throw new Error('VOICE_PRODUCER_ALREADY_EXISTS');
        if (state.producers.size >= 4) throw new Error('VOICE_SPEAKER_LIMIT_REACHED');
        const producer = await transport.produce({ kind: 'audio', rtpParameters, appData: { channelId, participantId } });
        state.producers.set(participantId, producer);
        return producer;
      };
      return;
    }
    default:
      throw new Error(`unknown mutation ${input.mutation}`);
  }
}

function record(execution: Execution, label: string, promise: Promise<unknown> | (() => unknown)): void {
  const call: Call = { label, settled: false };
  execution.calls.push(call);
  let result: Promise<unknown>;
  try {
    result = typeof promise === 'function' ? Promise.resolve(promise()) : promise;
  } catch (error) {
    result = Promise.reject(error);
  }
  result.then((value) => {
    call.settled = true;
    call.outcome = 'ok';
    onSuccess(execution, label, value);
  }, (error: unknown) => {
    call.settled = true;
    call.outcome = error instanceof Error ? error.message.split(' ')[0] : 'error';
  });
}

function onSuccess(execution: Execution, label: string, value: unknown): void {
  const [op, rest] = label.split('(');
  const args = (rest ?? '').replace(')', '').split(',');
  const participant = execution.participants.find((p) => p.id === args[0]);
  if (op === 'join' && participant) {
    const session = execution.coordinator.sessions.get(participant.id);
    if (!session || !session.router || session.router.closed) {
      execution.violations.push({ property: 'J1', message: `join(${participant.id}) succeeded without a live router` });
    }
  }
  if (op === 'transport') execution.transportIds.set(`${args[0]}:${args[1]}`, (value as { id: string }).id);
  if (op === 'consume') {
    const list = execution.consumerIds.get(args[0]) ?? [];
    list.push((value as { id: string }).id);
    execution.consumerIds.set(args[0], list);
  }
}

function enabledCalls(execution: Execution): string[] {
  if (execution.started >= input.maxOps || execution.closeSettled) return [];
  const out: string[] = [];
  const ops = new Set(input.ops);
  if (ops.has('join') && execution.joins < input.maxJoins) {
    for (const channel of input.channels) out.push(`join(p${execution.joins + 1},${channel})`);
  }
  for (const participant of execution.participants) {
    const p = participant.id;
    if (ops.has('leave')) out.push(`leave(${p})`);
    if (ops.has('transport')) for (const direction of ['send', 'recv']) out.push(`transport(${p},${direction})`);
    if (ops.has('connect')) for (const direction of ['send', 'recv']) {
      if (execution.transportIds.has(`${p}:${direction}`)) out.push(`connect(${p},${direction})`);
    }
    if (ops.has('produce')) out.push(`produce(${p})`);
    if (ops.has('closeProducer')) out.push(`closeProducer(${p})`);
    if (ops.has('consume')) for (const source of execution.participants) {
      if (source.id !== p) out.push(`consume(${p},${source.id})`);
    }
    if (ops.has('resume')) for (const consumerId of execution.consumerIds.get(p) ?? []) out.push(`resume(${p},${consumerId})`);
  }
  if (ops.has('close') && !execution.closeCalled) out.push('close()');
  return out;
}

function startCall(execution: Execution, label: string): void {
  const c = execution.coordinator;
  const [op, rest] = label.split('(');
  const args = rest.replace(')', '').split(',');
  execution.started++;
  const channelOf = (id: string) => CHANNEL_UUID[execution.participants.find((p) => p.id === id)!.channel];
  switch (op) {
    case 'join': {
      execution.joins++;
      execution.participants.push({ id: args[0], channel: args[1] });
      record(execution, label, () => c.joinParticipant(CHANNEL_UUID[args[1]], args[0]));
      return;
    }
    case 'leave':
      record(execution, label, () => c.leaveParticipant(args[0]));
      return;
    case 'transport':
      record(execution, label, () => c.createTransport(channelOf(args[0]), args[0], args[1]));
      return;
    case 'connect':
      record(execution, label, () => c.connectTransport(channelOf(args[0]), args[0], args[1],
        execution.transportIds.get(`${args[0]}:${args[1]}`), DTLS));
      return;
    case 'produce':
      record(execution, label, () => c.createProducer(channelOf(args[0]), args[0], RTP_PARAMETERS));
      return;
    case 'closeProducer':
      record(execution, label, () => c.closeProducer(channelOf(args[0]), args[0]));
      return;
    case 'consume':
      record(execution, label, () => c.createConsumer(channelOf(args[0]), args[0], args[1], RTP_CAPABILITIES));
      return;
    case 'resume':
      record(execution, label, () => c.resumeConsumer(channelOf(args[0]), args[0], args[1]));
      return;
    case 'close':
      execution.closeCalled = true;
      record(execution, label, async () => {
        await c.close();
        execution.closeSettled = true;
      });
      return;
    default:
      throw new Error(`unknown call ${label}`);
  }
}

function choices(execution: Execution): string[] {
  const out = enabledCalls(execution).map((label) => `call ${label}`);
  for (const entry of execution.world.pending) {
    out.push(`resolve ${entry.label}`);
    if (input.failures && !entry.label.startsWith('producerclose')) out.push(`fail ${entry.label}`);
  }
  return out;
}

async function apply(execution: Execution, choice: string): Promise<void> {
  if (choice.startsWith('call ')) {
    startCall(execution, choice.slice(5));
  } else {
    const fail = choice.startsWith('fail ');
    const label = choice.slice(fail ? 5 : 8);
    const entry = execution.world.pending.find((p) => p.label === label);
    if (!entry) throw new Error(`no pending ${label}`);
    entry.settle(fail);
  }
  await drain();
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

function channelOfUuid(uuid: unknown): string {
  return Object.entries(CHANNEL_UUID).find(([, value]) => value === uuid)?.[0] ?? String(uuid);
}

function check(execution: Execution): Array<{ property: string; message: string }> {
  const out = [...execution.violations];
  const c = execution.coordinator;
  const sessions: Map<string, { channelId: string; router: FakeRouter | null }> = c.sessions;
  const current = (participantId: unknown, channelId: unknown) => {
    const session = sessions.get(String(participantId));
    return Boolean(session && session.channelId === channelId);
  };
  const objects = execution.world.objects;
  const quiet = execution.world.pending.length === 0 && execution.calls.every((call) => call.settled);
  // I1/I2: media only flows (worker side) between current sessions of the same channel and router.
  for (const consumer of [...objects, ...execution.world.workerSide]) {
    if (!(consumer instanceof FakeConsumer) || !consumer.alive || consumer.paused || !consumer.producer.alive) continue;
    const producer = consumer.producer;
    if (consumer.appData.channelId !== producer.appData.channelId || consumer.transport.router !== producer.transport.router) {
      out.push({ property: 'I1', message: `${consumer.id} forwards ${producer.id} across channels or routers` });
    }
    if (!current(consumer.appData.participantId, consumer.appData.channelId)
      || !current(producer.appData.participantId, producer.appData.channelId)) {
      out.push({ property: 'I2', message: `${consumer.id} (${String(consumer.appData.participantId)} <- ${String(producer.appData.participantId)}) is open for a participant without a current session` });
    }
  }
  // I3: every open object is registered and belongs to a current session.
  const transportState: Map<string, { send?: FakeTransport; recv?: FakeTransport }> = c.transports.participants;
  const producerState: Map<string, { producers: Map<string, FakeProducer> }> = c.producers.channels;
  const consumerState: Map<string, Map<string, { consumers: Map<string, FakeConsumer> }>> = c.consumers.channels;
  for (const object of objects) {
    if (object.closed) continue;
    if (object instanceof FakeTransport) {
      const p = String(object.appData.participantId);
      const registered = transportState.get(p)?.[object.appData.direction as 'send' | 'recv'] === object;
      if (!registered) out.push({ property: 'I3', message: `open ${object.id} of ${p} is not registered (leak)` });
      else if (!sessions.has(p)) out.push({ property: 'I3', message: `registered ${object.id} of ${p} has no session` });
    } else if (object instanceof FakeProducer) {
      const p = String(object.appData.participantId);
      const registered = producerState.get(String(object.appData.channelId))?.producers.get(p) === object;
      if (!registered) out.push({ property: 'I3', message: `open ${object.id} of ${p} is not registered (leak)` });
      else if (!current(p, object.appData.channelId)) out.push({ property: 'I3', message: `registered ${object.id} of ${p} has no session` });
    } else if (object instanceof FakeConsumer) {
      const p = String(object.appData.participantId);
      const registered = consumerState.get(String(object.appData.channelId))?.get(p)?.consumers.get(String(object.appData.sourceParticipantId)) === object;
      if (!registered) out.push({ property: 'I3', message: `open ${object.id} of ${p} is not registered (leak)` });
      else if (!current(p, object.appData.channelId)) out.push({ property: 'I3', message: `registered ${object.id} of ${p} has no session` });
    }
  }
  // I4: limits.
  for (const [channel, state] of producerState) {
    const open = [...state.producers.values()].filter((p) => !p.closed).length;
    if (open > 4) out.push({ property: 'I4', message: `${open} producers in ${channelOfUuid(channel)}` });
  }
  for (const [, channel] of consumerState) {
    for (const [p, state] of channel) {
      const open = [...state.consumers.values()].filter((x) => !x.closed).length;
      if (open > 4) out.push({ property: 'I4', message: `${open} consumers for ${p}` });
    }
  }
  // I5: sessions use live routers; at most one live router per channel.
  for (const [p, session] of sessions) {
    if (session.router && session.router.closed) out.push({ property: 'I5', message: `session ${p} keeps a closed router` });
  }
  const liveRouters = objects.filter((o): o is FakeRouter => o instanceof FakeRouter && !o.closed);
  const routerMap: Map<string, FakeRouter[]> = c.routers.routers;
  const byChannel = new Map<string, number>();
  for (const router of liveRouters) {
    const entry = [...routerMap.entries()].find(([, list]) => list.includes(router));
    if (!entry) {
      out.push({ property: 'I5', message: `open ${router.id} is not registered (leak)` });
      continue;
    }
    byChannel.set(entry[0], (byChannel.get(entry[0]) ?? 0) + 1);
    // I6: once nothing is pending, a router exists only for a channel with participants.
    if (quiet && !c.channels.has(entry[0])) {
      out.push({ property: 'I6', message: `${router.id} stays open for empty channel ${channelOfUuid(entry[0])}` });
    }
  }
  for (const [channel, count] of byChannel) {
    if (count > 1) out.push({ property: 'I5', message: `${count} open routers for ${channelOfUuid(channel)}` });
  }
  // I7: after close() everything is closed, in Node and in the worker.
  if (execution.closeSettled) {
    const open = [...objects.filter((o) => !o.closed || o.alive), ...[...execution.world.workerSide].filter((o) => o.alive)];
    if (open.length || sessions.size || c.channels.size) {
      out.push({ property: 'I7', message: `after close(): open ${open.map((o) => o.id).join(',') || 'none'}, ${sessions.size} sessions` });
    }
  }
  return out;
}

function fingerprint(execution: Execution): string {
  const c = execution.coordinator;
  const ref = (object: Fake | null | undefined) => (object ? object.id : null);
  const sorted = <T,>(values: T[]) => values.map((v) => JSON.stringify(v)).sort();
  const state: Json = {
    sessions: sorted([...c.sessions.entries()].map(([p, s]: [string, any]) => [p, channelOfUuid(s.channelId), ref(s.router)])),
    channels: sorted([...c.channels.entries()].map(([ch, members]: [string, Set<string>]) => [channelOfUuid(ch), [...members].sort()])),
    routers: sorted([...c.routers.routers.entries()].map(([ch, list]: [string, FakeRouter[]]) => [channelOfUuid(ch), list.map(ref)])),
    routerPending: [...c.routers.pending.keys()].map(channelOfUuid).sort(),
    servers: sorted([...c.webRtcServers.servers.entries()].map(([w, s]: [FakeWorker, FakeServer]) => [ref(w), ref(s)])),
    serverPending: [...c.webRtcServers.pending.keys()].map((w: FakeWorker) => w.id).sort(),
    transports: sorted([...c.transports.participants.entries()].map(([p, s]: [string, any]) => [p, ref(s.send), ref(s.recv), [...s.pending].sort(), s.closed])),
    producers: sorted([...c.producers.channels.entries()].map(([ch, s]: [string, any]) => [channelOfUuid(ch),
      sorted([...s.producers.entries()].map(([p, x]: [string, FakeProducer]) => [p, ref(x)])), [...s.pending.keys()].sort()])),
    consumers: sorted([...c.consumers.channels.entries()].map(([ch, m]: [string, Map<string, any>]) => [channelOfUuid(ch),
      sorted([...m.entries()].map(([p, s]) => [p, sorted([...s.consumers.entries()].map(([src, x]: [string, FakeConsumer]) => [src, ref(x)])), [...s.pending.keys()].sort()]))])),
    worker: [...execution.world.workerSide].map((o) => [o.id, o.alive]).sort(),
    objects: execution.world.objects.map((o) => [o.id, o.closed, o.alive,
      o instanceof FakeConsumer ? [o.paused, ref(o.producer), ref(o.transport)] : o instanceof FakeProducer ? ref(o.transport)
        : o instanceof FakeTransport ? [ref(o.router), o.connected, String(o.appData.participantId), String(o.appData.direction)] : null]),
    pending: execution.world.pending.map((p) => p.label).sort(),
    calls: execution.calls.map((call) => [call.label, call.settled ? call.outcome ?? '' : '…']),
    flags: [c.ready, c.closed, execution.started, execution.joins, execution.closeCalled, execution.closeSettled],
    known: [[...execution.transportIds.entries()].sort(), [...execution.consumerIds.entries()].sort()],
  };
  return JSON.stringify(state);
}

// ---------------------------------------------------------------------------
// Breadth-first search over schedules
// ---------------------------------------------------------------------------

async function replay(schedule: string[]): Promise<Execution> {
  const execution = await fresh();
  if (input.scenario) await prepare(execution, input.scenario);
  for (const choice of schedule) await apply(execution, choice);
  return execution;
}

async function prepare(execution: Execution, scenario: string): Promise<void> {
  // A deterministic prefix with every request resolved in order.
  const settleAll = async () => {
    while (execution.world.pending.length) await apply(execution, `resolve ${execution.world.pending[0].label}`);
  };
  if (scenario === 'five-speakers') {
    for (let i = 1; i <= 5; i++) {
      startCall(execution, `join(p${i},X)`);
      await drain();
      await settleAll();
      startCall(execution, `transport(p${i},send)`);
      await drain();
      await settleAll();
    }
    execution.started = 0;
    return;
  }
  if (scenario === 'speaker-listener' || scenario === 'two-channels') {
    // p1 speaks in X; p2 listens in X (speaker-listener) or in Y (two-channels).
    const listenerChannel = scenario === 'two-channels' ? 'Y' : 'X';
    for (const call of ['join(p1,X)', `join(p2,${listenerChannel})`, 'transport(p1,send)', 'transport(p2,recv)', 'produce(p1)']) {
      startCall(execution, call);
      await drain();
      await settleAll();
    }
    execution.started = 0;
    return;
  }
  throw new Error(`unknown scenario ${scenario}`);
}

const seen = new Set<string>();
const queue: string[][] = [[]];
let executions = 0;
let transitions = 0;
const violations: Array<{ property: string; message: string; trace: string[] }> = [];
const found = new Set<string>();
const maxStates = input.maxStates ?? 2_000_000;
{
  const first = await replay([]);
  seen.add(fingerprint(first));
}
while (queue.length && seen.size < maxStates) {
  const schedule = queue.shift()!;
  const parent = await replay(schedule);
  executions++;
  const options = choices(parent);
  for (const choice of options) {
    const execution = await replay([...schedule, choice]);
    executions++;
    transitions++;
    const key = fingerprint(execution);
    if (seen.has(key)) continue;
    seen.add(key);
    const hits = check(execution);
    for (const hit of hits) {
      if (found.has(hit.property)) continue;
      found.add(hit.property);
      violations.push({ ...hit, trace: [...schedule, choice] });
    }
    if (!hits.length) queue.push([...schedule, choice]);
  }
  if (input.stop?.length && input.stop.every((p) => found.has(p))) break;
}

const stopped = Boolean(input.stop?.length && input.stop.every((p) => found.has(p)));
process.stdout.write(JSON.stringify({
  executions, states: seen.size, transitions, complete: queue.length === 0 || stopped, violations,
}));
