import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { AppLock, SettingsStore, defaultSettings } from './settings.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('desktop settings', () => {
  it('defaults closed when no connection has been configured', async () => {
    const root = await makeTemporaryDirectory();
    assert.deepEqual(await new SettingsStore(root).load(), defaultSettings());
  });

  it('normalizes and atomically persists bounded settings', async () => {
    const root = await makeTemporaryDirectory();
    const store = new SettingsStore(root);
    await store.save({ version: 1, serverUrl: 'https://chat.example.test/', idleLockMinutes: 15 });
    assert.deepEqual(await store.load(), {
      version: 1,
      serverUrl: 'https://chat.example.test',
      idleLockMinutes: 15,
    });
    assert.equal((await readFile(path.join(root, 'settings.json'), 'utf8')).endsWith('\n'), true);
  });

  it('does not honor malformed on-disk values', async () => {
    const root = await makeTemporaryDirectory();
    const store = new SettingsStore(root);
    await store.save({ version: 1, serverUrl: 'https://chat.example.test', idleLockMinutes: 5 });
    const settingsPath = path.join(root, 'settings.json');
    const original = await readFile(settingsPath, 'utf8');
    await import('node:fs/promises').then(({ writeFile }) => writeFile(
      settingsPath,
      original.replace('https://chat.example.test', 'file:///tmp/evil'),
      'utf8',
    ));
    assert.deepEqual(await store.load(), defaultSettings());
  });
});

describe('desktop app lock', () => {
  it('starts unlocked when no earlier run left a marker', async () => {
    const root = await makeTemporaryDirectory();
    const lock = new AppLock(root);
    await lock.load();
    assert.equal(lock.locked, false);
    assert.deepEqual(await readdir(root), []);
  });

  it('is still locked after a restart until the user unlocks', async () => {
    const root = await makeTemporaryDirectory();
    const marker = path.join(root, 'app-lock.json');
    const first = new AppLock(root);
    await first.load();
    await first.lock();
    assert.equal(first.locked, true);
    assert.equal((await readFile(marker, 'utf8')).endsWith('\n'), true);
    if (process.platform !== 'win32') assert.equal((await stat(marker)).mode & 0o777, 0o600);
    // Only the marker remains: the temporary file of the atomic write is gone.
    assert.deepEqual(await readdir(root), ['app-lock.json']);

    // Each new instance stands for a later start of the app.
    const second = new AppLock(root);
    await second.load();
    assert.equal(second.locked, true);
    const third = new AppLock(root);
    await third.load();
    assert.equal(third.locked, true);

    await third.unlock();
    assert.equal(third.locked, false);
    assert.deepEqual(await readdir(root), []);
    const fourth = new AppLock(root);
    await fourth.load();
    assert.equal(fourth.locked, false);
  });

  it('locks at once and saves the marker behind it', async () => {
    const root = await makeTemporaryDirectory();
    const lock = new AppLock(path.join(root, 'not', 'created', 'yet'));
    const saved = lock.lock();
    assert.equal(lock.locked, true);
    await saved;
    assert.deepEqual(await readdir(path.join(root, 'not', 'created', 'yet')), ['app-lock.json']);
  });

  it('leaves the marker matching the last request', async () => {
    const root = await makeTemporaryDirectory();
    const lock = new AppLock(root);
    // A lock requested while an unlock is still being written is not erased by it, and the
    // other way round.
    await Promise.all([lock.lock(), lock.unlock(), lock.lock()]);
    assert.equal(lock.locked, true);
    assert.deepEqual(await readdir(root), ['app-lock.json']);

    await Promise.all([lock.unlock(), lock.lock(), lock.unlock()]);
    assert.equal(lock.locked, false);
    assert.deepEqual(await readdir(root), []);

    void lock.lock();
    await lock.settled();
    assert.deepEqual(await readdir(root), ['app-lock.json']);
  });

  it('stays locked when the marker is damaged', async () => {
    for (const contents of ['', '{', 'unlocked', '{"version":1,"locked":false}\n']) {
      const root = await makeTemporaryDirectory();
      await writeFile(path.join(root, 'app-lock.json'), contents, 'utf8');
      const lock = new AppLock(root);
      await lock.load();
      assert.equal(lock.locked, true, JSON.stringify(contents));
      // Unlocking still works and removes the damaged file.
      await lock.unlock();
      assert.equal(lock.locked, false);
      assert.deepEqual(await readdir(root), []);
    }
  });

  it('stays locked when the marker cannot be read', { skip: process.platform === 'win32' }, async () => {
    const root = await makeTemporaryDirectory();
    await writeFile(path.join(root, 'user-data'), 'a file where the directory should be', 'utf8');
    const lock = new AppLock(path.join(root, 'user-data'));
    await lock.load();
    assert.equal(lock.locked, true);
  });

  it('stays locked when the marker cannot be removed', async () => {
    const root = await makeTemporaryDirectory();
    // A directory in the marker's place is something the unlock cannot remove.
    await mkdir(path.join(root, 'app-lock.json'));
    const lock = new AppLock(root);
    await lock.load();
    assert.equal(lock.locked, true);
    await assert.rejects(lock.unlock());
    assert.equal(lock.locked, true);
    await lock.settled();
  });

  it('stays locked and reports it when the marker cannot be saved', async () => {
    const root = await makeTemporaryDirectory();
    await writeFile(path.join(root, 'user-data'), 'a file where the directory should be', 'utf8');
    const lock = new AppLock(path.join(root, 'user-data'));
    await assert.rejects(lock.lock());
    assert.equal(lock.locked, true);
    await lock.settled();
  });

  it('can be unlocked when no marker was ever saved', async () => {
    const root = await makeTemporaryDirectory();
    const lock = new AppLock(root);
    await lock.unlock();
    assert.equal(lock.locked, false);
    assert.deepEqual(await readdir(root), []);
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'alparts-settings-'));
  temporaryDirectories.push(directory);
  return directory;
}
