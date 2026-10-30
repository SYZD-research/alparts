import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { EventEmitter } from 'node:events';
import type { types } from 'mediasoup';
import { VoiceWorkerManager } from './worker-manager.js';
import { VoiceCoordinator } from './voice-coordinator.js';

let nextPid = 1;

function fakeWorker() {
  const events = new EventEmitter();
  const worker = {
    pid: nextPid++,
    closed: false,
    on: events.on.bind(events),
    close() { this.closed = true; },
    die() {
      this.closed = true;
      events.emit('died', new Error('killed'));
    },
  };
  return worker as typeof worker & types.Worker;
}

async function until(condition: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe('media workers', () => {
  it('replaces a worker that died and keeps the others in use meanwhile', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const created: ReturnType<typeof fakeWorker>[] = [];
    const manager = new VoiceWorkerManager(async () => {
      const worker = fakeWorker();
      created.push(worker);
      return worker;
    });
    await manager.start(2);
    const [first, second] = created;
    first!.die();
    // Only the live worker takes new calls until the replacement is up.
    assert.equal(manager.getWorker(), second);
    assert.equal(manager.getWorker(), second);
    t.mock.timers.tick(1_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(created.length, 3);
    assert.deepEqual(new Set([manager.getWorker(), manager.getWorker()]), new Set([second, created[2]]));
    manager.close();
  });

  it('keeps trying to replace a worker while starting one fails', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let failures = 2;
    const created: ReturnType<typeof fakeWorker>[] = [];
    const manager = new VoiceWorkerManager(async () => {
      if (created.length > 0 && failures > 0) {
        failures--;
        throw new Error('spawn failed');
      }
      const worker = fakeWorker();
      created.push(worker);
      return worker;
    });
    await manager.start(1);
    created[0]!.die();
    assert.throws(() => manager.getWorker(), /VOICE_WORKERS_NOT_STARTED/);
    for (const delay of [1_000, 2_000, 4_000]) {
      t.mock.timers.tick(delay);
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(manager.getWorker(), created[1]);
    manager.close();
  });

  it('does not start a replacement after closing', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const created: ReturnType<typeof fakeWorker>[] = [];
    const manager = new VoiceWorkerManager(async () => {
      const worker = fakeWorker();
      created.push(worker);
      return worker;
    });
    await manager.start(1);
    created[0]!.die();
    manager.close();
    t.mock.timers.tick(60_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(created.length, 1);
  });

  it('ends only the calls of a real worker that died, and lets them join again on its replacement', async () => {
    const coordinator = new VoiceCoordinator({
      bindAddress: '127.0.0.1',
      announcedAddress: '127.0.0.1',
      basePort: 47000 + Math.floor(Math.random() * 1000),
      workerCount: 2,
    });
    try {
      await coordinator.start();
      const channelA = '00000000-0000-4000-8000-0000000000a1';
      const channelB = '00000000-0000-4000-8000-0000000000b1';
      const lost: string[] = [];
      coordinator.onSessionLost((_channelId, participantId) => lost.push(participantId));
      await coordinator.joinParticipant(channelA, 'a1');
      await coordinator.joinParticipant(channelA, 'a2');
      await coordinator.joinParticipant(channelB, 'b1');
      await coordinator.createTransport(channelA, 'a1', 'send');
      await coordinator.createTransport(channelB, 'b1', 'send');

      // Workers take routers in turn: channel A's is on the first one.
      const workers = (coordinator as unknown as { workers: { workers: types.Worker[] } }).workers.workers;
      const victim = workers[0]!;
      process.kill(victim.pid, 'SIGKILL');

      await until(() => lost.length === 2);
      assert.deepEqual(lost.sort(), ['a1', 'a2']);
      // The other channel's call keeps running.
      await coordinator.createTransport(channelB, 'b1', 'recv');

      await until(() => workers.length === 2 && !workers.includes(victim));
      await coordinator.joinParticipant(channelA, 'a1');
      await coordinator.createTransport(channelA, 'a1', 'send');
    } finally {
      await coordinator.close();
    }
  });
});
