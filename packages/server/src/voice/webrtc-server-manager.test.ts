import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { types } from 'mediasoup';
import { VoiceWebRtcServerManager } from './webrtc-server-manager.js';

/** A worker whose WebRTC servers fail while their port is busy. */
function fakeWorker(busy: Set<number>) {
  const ports: number[] = [];
  const worker = {
    closed: false,
    ports,
    async createWebRtcServer(options: { listenInfos: Array<{ port: number }> }) {
      const port = options.listenInfos[0]!.port;
      ports.push(port);
      if (busy.has(port)) throw new Error(`uv_udp_bind() failed [port:${port}]: address already in use`);
      return { closed: false, close() { this.closed = true; }, observer: { on() {} } };
    },
  };
  return worker as typeof worker & types.Worker;
}

describe('media server ports', () => {
  const config = { bindAddress: '127.0.0.1', announcedAddress: '127.0.0.1', basePort: 40000 };

  it('gives each worker its own port from the base port', async () => {
    const manager = new VoiceWebRtcServerManager(config);
    const first = fakeWorker(new Set());
    const second = fakeWorker(new Set());
    await manager.getOrCreate(first);
    await manager.getOrCreate(second);
    assert.deepEqual([first.ports, second.ports], [[40000], [40001]]);
  });

  it('tries the same port again after it was busy, instead of moving past the configured range', async () => {
    const busy = new Set([40000]);
    const manager = new VoiceWebRtcServerManager(config);
    const worker = fakeWorker(busy);
    await assert.rejects(manager.getOrCreate(worker), /address already in use/);
    await assert.rejects(manager.getOrCreate(worker), /address already in use/);
    busy.clear();
    await manager.getOrCreate(worker);
    assert.deepEqual(worker.ports, [40000, 40000, 40000]);
  });

  it('gives the port of a closed worker to the next one', async () => {
    const manager = new VoiceWebRtcServerManager(config);
    const first = fakeWorker(new Set());
    await manager.getOrCreate(first);
    first.closed = true;
    const next = fakeWorker(new Set());
    await manager.getOrCreate(next);
    assert.deepEqual(next.ports, [40000]);
  });
});
