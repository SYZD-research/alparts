import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { SettingsStore, defaultSettings } from './settings.js';

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

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'alparts-settings-'));
  temporaryDirectories.push(directory);
  return directory;
}
