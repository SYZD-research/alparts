import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  assertSafeSelectedPath,
  isDangerousDownloadFilename,
  MAX_NATIVE_SAVE_CHUNK_BYTES,
  NativeFileSaveManager,
  normalizeSuggestedFilename,
} from './file-save.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('native attachment saving', () => {
  it('normalizes names and detects active or disguised extensions', () => {
    assert.equal(normalizeSuggestedFilename('../../CON.exe '), '.._.._CON.exe');
    assert.equal(normalizeSuggestedFilename('....'), 'attachment');
    assert.equal(isDangerousDownloadFilename('report.txt'), false);
    assert.equal(isDangerousDownloadFilename('report.pdf.exe'), true);
    assert.equal(isDangerousDownloadFilename('sample.JS::$DATA'), true);
    assert.equal(assertSafeSelectedPath('/tmp/report.txt'), '/tmp/report.txt');
    assert.throws(() => assertSafeSelectedPath('relative.txt'));
    assert.throws(() => assertSafeSelectedPath('C:\\safe\\report.txt:stream', 'win32'));
    assert.throws(() => assertSafeSelectedPath('C:\\safe\\CON.txt', 'win32'));
  });

  it('streams a bounded file through an opaque handle before publishing it', async () => {
    const directory = await makeTemporaryDirectory();
    const target = path.join(directory, 'saved.bin');
    let protectedDangerous: boolean | null = null;
    const manager = new NativeFileSaveManager(
      async (suggested) => {
        assert.equal(suggested, 'saved.bin');
        return target;
      },
      async (filename, dangerous) => {
        protectedDangerous = dangerous;
        await chmod(filename, 0o600);
      },
    );
    const token = await manager.begin('saved.bin', 6, false);
    assert.ok(token);
    await manager.write(token, Uint8Array.from([1, 2, 3]).buffer);
    await manager.write(token, Uint8Array.from([4, 5, 6]).buffer);
    assert.equal(await manager.finish(token), true);
    assert.deepEqual([...await readFile(target)], [1, 2, 3, 4, 5, 6]);
    assert.equal(protectedDangerous, false);
    if (process.platform !== 'win32') assert.equal((await stat(target)).mode & 0o777, 0o600);
  });

  it('removes incomplete files on cancellation and rejects size violations', async () => {
    const directory = await makeTemporaryDirectory();
    const target = path.join(directory, 'sample.exe');
    const manager = new NativeFileSaveManager(async () => target, async () => undefined);
    const token = await manager.begin('sample.exe', 2, false);
    assert.ok(token);
    await manager.write(token, Uint8Array.of(1).buffer);
    await assert.rejects(manager.finish(token));
    await assert.rejects(stat(target));

    const second = await manager.begin('sample.bin', 1, false);
    assert.ok(second);
    await assert.rejects(manager.write(second, new ArrayBuffer(MAX_NATIVE_SAVE_CHUNK_BYTES + 1)));
    assert.equal(await manager.cancel(second), false);
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'alparts-desktop-save-'));
  temporaryDirectories.push(directory);
  return directory;
}
