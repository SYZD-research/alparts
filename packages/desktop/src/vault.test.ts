import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { SecretVault, type VaultCrypto } from './vault.js';

const deviceId = '11111111-1111-4111-8111-111111111111';
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

class FakeCrypto implements VaultCrypto {
  reEncrypt = false;

  async available() { return true; }
  async encrypt(value: string) { return Buffer.from(`protected:${value}`, 'utf8'); }
  async decrypt(value: Buffer) {
    const encoded = value.toString('utf8');
    if (!encoded.startsWith('protected:')) throw new Error('invalid');
    const shouldReEncrypt = this.reEncrypt;
    this.reEncrypt = false;
    return { result: encoded.slice('protected:'.length), shouldReEncrypt };
  }
}

describe('desktop secret vault', () => {
  it('stores only protected bytes under an opaque filename', async () => {
    const root = await makeTemporaryDirectory();
    const vault = new SecretVault(root, new FakeCrypto());
    const secret = 'private-key-material';
    await vault.set('deployment', `device:${deviceId}`, secret);
    assert.equal(await vault.get('deployment', `device:${deviceId}`), secret);

    const [filename] = await readdir(path.join(root, 'vault', 'deployment'));
    assert.equal(filename.includes(deviceId), false);
    assert.equal((await readFile(path.join(root, 'vault', 'deployment', filename), 'utf8')).includes(secret), false);
  });

  it('rewrites a record when the platform key provider rotates', async () => {
    const root = await makeTemporaryDirectory();
    const crypto = new FakeCrypto();
    const vault = new SecretVault(root, crypto);
    await vault.set('deployment', `device:${deviceId}`, 'secret');
    crypto.reEncrypt = true;
    assert.equal(await vault.get('deployment', `device:${deviceId}`), 'secret');
  });

  it('deletes one record or an entire deployment namespace', async () => {
    const root = await makeTemporaryDirectory();
    const vault = new SecretVault(root, new FakeCrypto());
    await vault.set('deployment', `device:${deviceId}`, 'secret');
    await vault.delete('deployment', `device:${deviceId}`);
    assert.equal(await vault.get('deployment', `device:${deviceId}`), null);
    await vault.set('deployment', `device:${deviceId}`, 'secret');
    await vault.deleteNamespace('deployment');
    assert.equal(await vault.get('deployment', `device:${deviceId}`), null);
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'alparts-vault-'));
  temporaryDirectories.push(directory);
  return directory;
}
