// Real-service check of calls through the SFU with frame encryption (formal
// model M8, VE2 and M8k). Runs the server (with mediasoup workers) on a new
// disposable database, the client test page (packages/client/e2e) through
// Vite, and one headless Chromium context per participant with a fake
// microphone. The server side of this process also plays a malicious SFU: it
// reads every forwarded frame, relabels a stream, and replays frames.
//
// Requires what service-audit.mts requires (disposable PostgreSQL administrator
// URL, S3-compatible bucket, NODE_ENV=test, CORS_ORIGINS with
// http://localhost:5173) and a Playwright package (PLAYWRIGHT_MODULE, default
// 'playwright-core') with Chromium (CHROMIUM_PATH). Exit 1: a claimed property
// has a counterexample; 2: fixture or environment error.
// VOICE_E2E_CONTROL=plaintext-frames runs the clients with a frame worker that
// encrypts nothing; the frame checks must then report findings.
import assert from 'node:assert/strict';
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

assert.equal(process.env.RUN_VOICE_E2E, '1', 'Set RUN_VOICE_E2E=1 for this disposable integration check');
assert.match(new URL(process.env.DATABASE_URL!).pathname, /^\/alparts_(?:security_)?test(?:_\w+)?$/);
assert.equal(process.env.NODE_ENV, 'test');

const server = fileURLToPath(new URL('../../packages/server/', import.meta.url));
const clientRoot = fileURLToPath(new URL('../../packages/client/', import.meta.url));
const pg = createRequire(join(server, 'package.json'))('pg');
const ORIGIN = 'http://localhost:5173';
const admin = new pg.Client({ connectionString: process.env.DATABASE_URL });
const databaseName = `alparts_test_voice_${randomBytes(6).toString('hex')}`;
const directory = await mkdtemp(join(tmpdir(), 'alparts-voice-e2e-'));
const checks: Array<{ id: string; title: string; verdict: 'PASS' | 'FINDING'; detail?: string; measured?: Record<string, number> }> = [];
const cleanup: Array<() => Promise<unknown> | unknown> = [];
/** Levels and counts a check measured, reported with its verdict. */
let measured: Record<string, number> = {};
const note = (name: string, value: number) => { measured[name] = Math.round(value * 10_000) / 10_000; return value; };

async function check(id: string, title: string, run: () => Promise<void>): Promise<void> {
  measured = {};
  try {
    await run();
    checks.push({ id, title, verdict: 'PASS', measured });
  } catch (error) {
    if (!(error instanceof assert.AssertionError)) throw error;
    checks.push({ id, title, verdict: 'FINDING', detail: error.message, measured });
  }
  console.log(JSON.stringify(checks.at(-1)));
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually<T>(what: string, probe: () => Promise<T>, ok: (value: T) => boolean, ms = 30_000): Promise<T> {
  const deadline = Date.now() + ms;
  let last: T;
  do {
    last = await probe();
    if (ok(last)) return last;
    await sleep(250);
  } while (Date.now() < deadline);
  throw new Error(`fixture: ${what} (last: ${JSON.stringify(last)})`);
}

// --- RTP --------------------------------------------------------------------

interface RtpPacket { payloadType: number; sequence: number; timestamp: number; ssrc: number; payload: Buffer }

function parseRtp(packet: Buffer): RtpPacket | null {
  if (packet.length < 12 || packet[0]! >> 6 !== 2) return null;
  const payloadType = packet[1]! & 0x7f;
  if (payloadType >= 72 && payloadType <= 76) return null;   // RTCP
  let offset = 12 + (packet[0]! & 0x0f) * 4;
  if (packet[0]! & 0x10) {
    if (packet.length < offset + 4) return null;
    offset += 4 + packet.readUInt16BE(offset + 2) * 4;
  }
  let end = packet.length;
  if (packet[0]! & 0x20) end -= packet[packet.length - 1]!;
  if (offset > end) return null;
  return {
    payloadType,
    sequence: packet.readUInt16BE(2),
    timestamp: packet.readUInt32BE(4),
    ssrc: packet.readUInt32BE(8),
    payload: packet.subarray(offset, end),
  };
}

function buildRtp(payloadType: number, sequence: number, timestamp: number, ssrc: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(12);
  header[0] = 0x80;
  header[1] = payloadType & 0x7f;
  header.writeUInt16BE(sequence & 0xffff, 2);
  header.writeUInt32BE(timestamp >>> 0, 4);
  header.writeUInt32BE(ssrc >>> 0, 8);
  return Buffer.concat([header, payload]);
}

async function udpSocket(): Promise<UdpSocket> {
  const socket = createSocket('udp4');
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  cleanup.push(() => socket.close());
  return socket;
}

/**
 * A port the SFU can listen on (UDP and TCP), below the ephemeral range: a
 * random port inside it can be held for a moment by another UDP socket.
 */
async function freeMediaPort(): Promise<number> {
  const bindable = async (port: number) => {
    const udp = createSocket('udp4');
    const tcp = createServer();
    try {
      await new Promise<void>((resolve, reject) => { udp.once('error', reject); udp.bind(port, '127.0.0.1', () => resolve()); });
      await new Promise<void>((resolve, reject) => { tcp.once('error', reject); tcp.listen(port, '127.0.0.1', () => resolve()); });
      return true;
    } catch {
      return false;
    } finally {
      udp.close();
      tcp.close();
    }
  };
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const port = randomInt(20_000, 32_000);
    if (await bindable(port)) return port;
  }
  throw new Error('fixture: no free port for the SFU');
}

let exitCode = 0;
try {
  await admin.connect();
  await admin.query(`CREATE DATABASE ${databaseName}`);
  const url = new URL(process.env.DATABASE_URL!);
  url.pathname = '/' + databaseName;
  process.env.DATABASE_URL = url.toString();
  process.env.AUDIT_CHECKPOINT_PATH = join(directory, 'checkpoint.json');
  process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
  process.env.AUDIT_HEAD_OBJECT_KEY = `test-${randomUUID()}`;
  process.env.VOICE_SFU_ENABLED = 'true';
  process.env.VOICE_SFU_BIND_ADDRESS = '127.0.0.1';
  process.env.VOICE_SFU_ANNOUNCED_ADDRESS = '127.0.0.1';
  process.env.VOICE_SFU_BASE_PORT = String(await freeMediaPort());
  process.env.VOICE_SFU_WORKERS = '1';
  const migrated = spawnSync(process.execPath, ['--import', './node_modules/tsx/dist/loader.mjs', 'src/scripts/migrate-runtime.ts'], {
    cwd: server, env: process.env, encoding: 'utf8', timeout: 60_000,
  });
  if (migrated.status !== 0) throw new Error(`fixture migration failed: ${migrated.stderr}`);

  const database = await import('../../packages/server/src/db/index.ts');
  cleanup.push(() => database.closeDb());
  const { db } = database;
  const schema = await import('../../packages/server/src/db/schema.ts');
  const { Permissions } = await import('../../packages/shared/src/index.ts');
  const { config } = await import('../../packages/server/src/config/index.ts');
  const audit = await import('../../packages/server/src/middleware/audit.ts');
  const authService = await import('../../packages/server/src/services/auth.service.ts');
  const { decodeSFrameHeader } = await import('../../packages/client/src/services/sframe.ts');
  await audit.provisionAuditCheckpoint();
  const runtime = await (await import('../../packages/server/src/security/runtime-lease.ts')).acquireRuntimeLease();
  cleanup.push(() => runtime.close());
  const { httpServer, io } = (await import('../../packages/server/src/app.ts')).createApp();
  const coordinator = await (await import('../../packages/server/src/websocket/index.ts')).startVoiceSfu(io);
  assert.ok(coordinator, 'fixture: the SFU did not start');
  cleanup.push(() => coordinator.close());
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  cleanup.push(() => new Promise((resolve) => { io.close(); httpServer.close(resolve); }));
  const backend = `http://127.0.0.1:${(httpServer.address() as import('node:net').AddressInfo).port}`;

  // Every key message as the server relays it: who announced which key id to whom, and when.
  const announced: Array<{ sender: string; target: string; keyId: number; at: number }> = [];
  io.on('connection', (socket) => {
    socket.onAny((event: string, payload: any) => {
      if (event === 'voice:key' && payload && typeof payload.keyId === 'number') {
        announced.push({ sender: payload.senderParticipantId, target: payload.targetParticipantId, keyId: payload.keyId, at: Date.now() });
      }
    });
  });

  // Three members who may connect to one voice channel.
  const workspaceId = randomUUID();
  const channelId = randomUUID();
  const names = ['a', 'b', 'c'] as const;
  const users = Object.fromEntries(names.map((name) => [name, randomUUID()])) as Record<(typeof names)[number], string>;
  for (const name of names) {
    await db.insert(schema.users).values({ id: users[name], email: `${users[name]}@voice.invalid`, passwordHash: 'disabled-test-fixture', displayName: name.toUpperCase() });
  }
  await db.insert(schema.workspaces).values({ id: workspaceId, name: 'Voice check', ownerId: users.a });
  const roleId = randomUUID();
  await db.insert(schema.roles).values({ id: roleId, workspaceId, name: 'Member', position: 10, permissions: Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE | Permissions.SEND_MESSAGES });
  for (const name of names) {
    const [member] = await db.insert(schema.workspaceMembers).values({ workspaceId, userId: users[name] }).returning();
    await db.insert(schema.memberRoles).values({ memberId: member!.id, roleId });
  }
  await db.insert(schema.channels).values({ id: channelId, workspaceId, name: 'call', type: 'voice', isPrivate: false });

  // The client test page through Vite, proxied to this server.
  const { createServer: createVite } = await import(new URL('node_modules/vite/dist/node/index.js', `file://${clientRoot}`).href);
  const vite = await createVite({
    root: clientRoot,
    configFile: join(clientRoot, 'vite.config.ts'),
    logLevel: 'error',
    server: {
      port: 5173,
      strictPort: true,
      host: 'localhost',
      proxy: { '/api': backend, '/socket.io': { target: backend, ws: true } },
    },
  });
  await vite.listen();
  cleanup.push(() => vite.close());

  const playwright = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright-core');
  const browser = await playwright.chromium.launch({
    executablePath: process.env.CHROMIUM_PATH,
    args: [
      '--use-fake-ui-for-media-stream',
      '--use-fake-device-for-media-stream',
      '--autoplay-policy=no-user-gesture-required',
      '--allow-loopback-in-peer-connection',
    ],
  });
  cleanup.push(() => browser.close());

  interface Participant { name: string; userId: string; page: any; id: string | null }
  const participants: Record<string, Participant> = {};
  for (const name of names) {
    const user = await db.query.users.findFirst({ where: (table, { eq }) => eq(table.id, users[name]) });
    const session = await authService.establishSession(user!, undefined, 'passkey');
    const context = await browser.newContext();
    await context.grantPermissions(['microphone'], { origin: ORIGIN });
    await context.addCookies([{ name: config.auth.cookieName, value: session.token, url: ORIGIN, httpOnly: true, sameSite: 'Strict' }]);
    const page = await context.newPage();
    page.on('pageerror', (error: Error) => console.error(`[${name}] page error: ${error.message}`));
    await page.goto(`${ORIGIN}/e2e/voice-call.html${process.env.VOICE_E2E_CONTROL ? `?control=${encodeURIComponent(process.env.VOICE_E2E_CONTROL)}` : ''}`);
    await page.waitForFunction(() => document.title === 'voice call test page ready', undefined, { timeout: 60_000 });
    participants[name] = { name, userId: users[name], page, id: null };
  }
  const start = async (name: string) => {
    const state = await participants[name]!.page.evaluate((id: string) => (window as any).voiceCall.start(id), channelId);
    assert.equal(state.status, 'connected', `fixture: ${name} did not join: ${state.error}`);
    participants[name]!.id = state.self;
  };
  const level = (listener: string, speaker: string, ms = 2_000): Promise<number> => (
    participants[listener]!.page.evaluate(([id, duration]: [string, number]) => (window as any).voiceCall.level(id, duration), [participants[speaker]!.id, ms])
  );
  const hears = async (listener: string, speaker: string) => note(`${listener} hears ${speaker}`, await eventually(
    `${listener} hears ${speaker}`, () => level(listener, speaker), (value) => value > 0.01,
  ));
  const socketOf = (name: string) => [...io.sockets.sockets.values()].find((socket: any) => socket.userId === participants[name]!.userId)!;
  const producerOf = (name: string) => (coordinator as any).producers.getProducer(channelId, participants[name]!.id);
  const router = () => (coordinator as any).routers.getRouters(channelId)[0];

  /** What the SFU forwards from a participant, read at the SFU for `ms` milliseconds. */
  async function capture(name: string, ms: number): Promise<RtpPacket[]> {
    const producer = producerOf(name);
    assert.ok(producer, `fixture: no stream from ${name}`);
    const socket = await udpSocket();
    const packets: RtpPacket[] = [];
    socket.on('message', (message) => {
      const packet = parseRtp(message);
      if (packet) packets.push(packet);
    });
    const transport = await router().createPlainTransport({ listenInfo: { protocol: 'udp', ip: '127.0.0.1' }, rtcpMux: true, comedia: false });
    await transport.connect({ ip: '127.0.0.1', port: socket.address().port });
    const consumer = await transport.consume({ producerId: producer.id, rtpCapabilities: router().rtpCapabilities, paused: false });
    await sleep(ms);
    consumer.close();
    transport.close();
    return packets;
  }

  /** Every payload is an SFrame ciphertext under a key its sender announced; counters never repeat. */
  function assertCiphertext(name: string, packets: RtpPacket[]): Set<number> {
    assert.ok(packets.length > 20, `${name}: too few packets at the SFU (${packets.length})`);
    note(`${name} frames read at the SFU`, (measured[`${name} frames read at the SFU`] ?? 0) + packets.length);
    const keys = new Set(announced.filter((entry) => entry.sender === participants[name]!.id).map((entry) => entry.keyId));
    const counters = new Map<number, Set<bigint>>();
    for (const packet of packets) {
      const header = decodeSFrameHeader(packet.payload);
      assert.ok(header && packet.payload.length >= header.length + 16, `${name}: a forwarded payload is not an SFrame ciphertext`);
      const kid = Number(header.kid);
      assert.ok(keys.has(kid), `${name}: a forwarded frame is under key ${kid}, which ${name} never announced`);
      const seen = counters.get(kid) ?? new Set<bigint>();
      assert.ok(!seen.has(header.ctr), `${name}: counter ${header.ctr} repeats under key ${kid}`);
      seen.add(header.ctr);
      counters.set(kid, seen);
    }
    return new Set(counters.keys());
  }

  await start('a');
  await start('b');
  let early: RtpPacket[] = [];
  await check('VE2-e2e-audio', 'Through the SFU, each participant hears the others', async () => {
    await hears('a', 'b');
    await hears('b', 'a');
  });
  await check('VE2-e2e-ciphertext', 'Every frame the SFU forwards is an SFrame ciphertext under a key its sender announced in a signed key message', async () => {
    early = await capture('a', 2_000);
    assertCiphertext('a', early);
    assertCiphertext('b', await capture('b', 2_000));
  });

  const beforeC = Date.now();
  await start('c');
  await check('VK-e2e-join', 'A newcomer gets only keys made after it joined, and hears everyone', async () => {
    for (const [listener, speaker] of [['c', 'a'], ['c', 'b'], ['a', 'c'], ['b', 'c']] as const) await hears(listener, speaker);
    const usedBefore = new Set(announced.filter((entry) => entry.at < beforeC).map((entry) => entry.keyId));
    const toC = announced.filter((entry) => entry.target === participants.c!.id);
    assert.ok(toC.length >= 2, 'c received no keys');
    for (const entry of toC) assert.ok(!usedBefore.has(entry.keyId), `c received key ${entry.keyId}, used before it joined`);
    // The keys a and b send under now are among those c received.
    const now = assertCiphertext('a', await capture('a', 1_500));
    assert.ok([...now].every((kid) => toC.some((entry) => entry.keyId === kid)), 'a sends under a key c never received');
  });

  await check('VK-e2e-attribution', 'A stream the server serves as another participant\'s is not played', async () => {
    const producers = (coordinator as any).producers;
    const original = producers.getProducer.bind(producers);
    const real = producerOf('a');
    producers.getProducer = (channel: string, participantId: string) => (
      participantId === participants.c!.id ? real : original(channel, participantId)
    );
    try {
      // The server drops b's stream of c and tells b that c's stream is now a's.
      (coordinator as any).consumers.closeConsumer(channelId, participants.b!.id, participants.c!.id);
      socketOf('b').emit('voice:sfu:producer', { channelId, participantId: participants.c!.id, producerId: real.id });
      await sleep(2_000);
      const relabelled = note("b plays a's frames served as c's", await level('b', 'c', 3_000));
      assert.ok(relabelled < 0.002, `b plays a's frames as c's (level ${relabelled.toFixed(4)})`);
      await hears('b', 'a');
    } finally {
      producers.getProducer = original;
    }
  });

  await participants.c!.page.evaluate(() => (window as any).voiceCall.leave());
  await eventually('a and b see c leave', async () => (await Promise.all(['a', 'b'].map((name) => participants[name]!.page.evaluate(() => (window as any).voiceCall.state())))).map((state: any) => state.participants.length), (counts) => counts.every((count: number) => count === 2));
  await sleep(1_500);
  await check('VK-e2e-leave', 'After someone leaves, the others send only under keys it never received', async () => {
    const toC = new Set(announced.filter((entry) => entry.target === participants.c!.id).map((entry) => entry.keyId));
    for (const name of ['a', 'b']) {
      const used = assertCiphertext(name, await capture(name, 2_000));
      for (const kid of used) assert.ok(!toC.has(kid), `${name} still sends under key ${kid}, which c holds`);
    }
    await hears('a', 'b');
    await hears('b', 'a');
  });

  await check('VK-e2e-replay', 'Frames the server holds back reach a participant once; served again, they are not played', async () => {
    const producers = (coordinator as any).producers;
    const consumers = (coordinator as any).consumers;
    // The server holds back a's frames from b for three seconds and records them.
    const toB = consumers.getConsumer(channelId, participants.b!.id, participants.a!.id);
    assert.ok(toB, 'fixture: b does not receive a');
    await toB.pause();
    const held = await capture('a', 3_000);
    assert.ok(held.length > 40, `fixture: too few held-back frames (${held.length})`);
    // ... then serves them to b as a new stream from a, twice.
    const injectTransport = await router().createPlainTransport({ listenInfo: { protocol: 'udp', ip: '127.0.0.1' }, rtcpMux: true, comedia: true });
    const codec = router().rtpCapabilities.codecs.find((entry: any) => entry.mimeType === 'audio/opus');
    const ssrc = 0x2222_2222;
    const injected = await injectTransport.produce({
      kind: 'audio',
      rtpParameters: { codecs: [{ mimeType: 'audio/opus', payloadType: codec.preferredPayloadType, clockRate: 48_000, channels: 2, parameters: {}, rtcpFeedback: [] }], encodings: [{ ssrc }] },
    });
    const original = producers.getProducer.bind(producers);
    producers.getProducer = (channel: string, participantId: string) => (
      participantId === participants.a!.id ? injected : original(channel, participantId)
    );
    const sender = await udpSocket();
    const play = async () => {
      let sequence = randomInt(0, 0xffff);
      let timestamp = randomInt(0, 0x7fff_ffff);
      const measured = level('b', 'a', held.length * 20 + 500);
      for (const packet of held) {
        sender.send(buildRtp(codec.preferredPayloadType, sequence++, timestamp, ssrc, packet.payload), injectTransport.tuple.localPort, '127.0.0.1');
        timestamp += 960;
        await sleep(20);
      }
      return measured;
    };
    try {
      consumers.closeConsumer(channelId, participants.b!.id, participants.a!.id);
      socketOf('b').emit('voice:sfu:producer', { channelId, participantId: participants.a!.id, producerId: injected.id });
      await sleep(1_500);
      // Not seen by b yet: genuine frames of a, only late. They are played (delay is not detected).
      const first = note('b plays the held-back frames', await play());
      assert.ok(first > 0.01, `b did not play a's held-back frames (level ${first.toFixed(4)}), so the replay below proves nothing`);
      // The same frames again.
      const again = note('b plays them again', await play());
      assert.ok(again < 0.002, `b played a's frames a second time (level ${again.toFixed(4)})`);
    } finally {
      producers.getProducer = original;
      injected.close();
      injectTransport.close();
    }
  });

  console.log(JSON.stringify({ summary: checks.reduce((counts, entry) => ({ ...counts, [entry.verdict]: (counts[entry.verdict] ?? 0) + 1 }), {} as Record<string, number>) }));
  exitCode = checks.some((entry) => entry.verdict === 'FINDING') ? 1 : 0;
} catch (error) {
  console.error(error);
  exitCode = 2;
} finally {
  for (const step of cleanup.reverse()) {
    try { await step(); } catch { /* keep cleaning up */ }
  }
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const { rows } = await admin.query('select count(*)::int as open from pg_stat_activity where datname = $1', [databaseName])
      .catch(() => ({ rows: [{ open: 0 }] })) as { rows: Array<{ open: number }> };
    if (rows[0]!.open === 0) break;
    await sleep(100);
  }
  await admin.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`).catch(() => undefined);
  await admin.end().catch(() => undefined);
  await rm(directory, { recursive: true, force: true });
  process.exit(exitCode);
}
