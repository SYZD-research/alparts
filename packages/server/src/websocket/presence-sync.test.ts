import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { UserStatusType } from '@alparts/shared';
import { PresenceSynchronizer, type PresenceStore } from './presence-sync.js';

function fakeStore(initial: UserStatusType = 'offline') {
  let connections = 0;
  let status: UserStatusType = initial;
  const broadcasts: UserStatusType[] = [];
  let releaseWrite: (() => void) | null = null;
  let holdWrites = false;
  const store: PresenceStore = {
    countConnections: async () => connections,
    readStatus: async () => status,
    writeStatus: async (_userId, next) => {
      if (holdWrites) await new Promise<void>((resolve) => { releaseWrite = resolve; });
      status = next;
    },
    broadcast: async (_userId, next) => { broadcasts.push(next); },
  };
  return {
    store,
    broadcasts,
    get status() { return status; },
    set connections(value: number) { connections = value; },
    holdNextWrite() { holdWrites = true; },
    release() { holdWrites = false; releaseWrite?.(); releaseWrite = null; },
  };
}

describe('presence synchronizer', () => {
  it('goes online on the first connection and offline after the last', async () => {
    const fake = fakeStore();
    const presence = new PresenceSynchronizer(fake.store);
    fake.connections = 1;
    await presence.sync('u');
    fake.connections = 2;
    await presence.sync('u');
    fake.connections = 1;
    await presence.sync('u');
    fake.connections = 0;
    await presence.sync('u');
    assert.deepEqual(fake.broadcasts, ['online', 'offline']);
    assert.equal(fake.status, 'offline');
  });

  it('never ends offline when a reconnect overlaps the previous disconnect', async () => {
    const fake = fakeStore('online');
    const presence = new PresenceSynchronizer(fake.store);
    // The old socket disconnects; its offline write is still in flight when
    // the new socket connects.
    fake.connections = 0;
    fake.holdNextWrite();
    const disconnect = presence.sync('u');
    await new Promise((resolve) => setImmediate(resolve));
    fake.connections = 1;
    const connect = presence.sync('u');
    fake.release();
    await Promise.all([disconnect, connect]);
    assert.equal(fake.status, 'online');
    assert.equal(fake.broadcasts.at(-1), 'online');
  });

  it('keeps a chosen status while connected and ignores choices without a connection', async () => {
    const fake = fakeStore();
    const presence = new PresenceSynchronizer(fake.store);
    await presence.choose('u', 'dnd');
    assert.equal(fake.status, 'offline');
    fake.connections = 1;
    await presence.sync('u');
    await presence.choose('u', 'dnd');
    fake.connections = 2;
    await presence.sync('u');
    assert.equal(fake.status, 'dnd');
    fake.connections = 0;
    await presence.sync('u');
    assert.deepEqual(fake.broadcasts, ['online', 'dnd', 'offline']);
  });

  it('continues after a failed store operation', async () => {
    const fake = fakeStore();
    let fail = true;
    const presence = new PresenceSynchronizer({
      ...fake.store,
      countConnections: async () => {
        if (fail) { fail = false; throw new Error('db down'); }
        return 1;
      },
    });
    await assert.rejects(presence.sync('u'), /db down/);
    await presence.sync('u');
    assert.equal(fake.status, 'online');
  });
});
