import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { assertSecretName, assertSecretValue } from './security-policy.js';

interface EncryptedPayload {
  version: 1;
  ciphertext: string;
}

export interface VaultCrypto {
  available(): Promise<boolean>;
  encrypt(value: string): Promise<Buffer>;
  decrypt(value: Buffer): Promise<{ result: string; shouldReEncrypt: boolean }>;
}

export class SecretVault {
  readonly #root: string;
  readonly #crypto: VaultCrypto;

  constructor(userDataDirectory: string, crypto: VaultCrypto) {
    this.#root = path.join(userDataDirectory, 'vault');
    this.#crypto = crypto;
  }

  async available(): Promise<boolean> {
    return this.#crypto.available();
  }

  async get(namespace: string, name: unknown): Promise<string | null> {
    const safeName = assertSecretName(name);
    const filename = this.#filename(namespace, safeName);
    let payload: EncryptedPayload;
    try {
      payload = JSON.parse(await readFile(filename, 'utf8')) as EncryptedPayload;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw new Error('VAULT_READ_FAILED');
    }
    if (payload.version !== 1 || typeof payload.ciphertext !== 'string' || payload.ciphertext.length > 256 * 1024) {
      throw new Error('VAULT_RECORD_INVALID');
    }
    let encrypted: Buffer;
    try {
      encrypted = Buffer.from(payload.ciphertext, 'base64');
      if (encrypted.length < 1 || encrypted.toString('base64') !== payload.ciphertext) throw new Error('invalid');
    } catch {
      throw new Error('VAULT_RECORD_INVALID');
    }
    const decrypted = await this.#crypto.decrypt(encrypted);
    const result = assertSecretValue(decrypted.result);
    if (decrypted.shouldReEncrypt) await this.set(namespace, safeName, result);
    return result;
  }

  async set(namespace: string, name: unknown, value: unknown): Promise<void> {
    const safeName = assertSecretName(name);
    const safeValue = assertSecretValue(value);
    if (!await this.available()) throw new Error('SECURE_STORAGE_UNAVAILABLE');
    const directory = this.#directory(namespace);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const filename = this.#filename(namespace, safeName);
    const temporary = path.join(directory, `.${randomUUID()}.tmp`);
    const encrypted = await this.#crypto.encrypt(safeValue);
    const payload: EncryptedPayload = { version: 1, ciphertext: encrypted.toString('base64') };
    try {
      await writeFile(temporary, `${JSON.stringify(payload)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      await rename(temporary, filename);
    } finally {
      encrypted.fill(0);
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  }

  async delete(namespace: string, name: unknown): Promise<void> {
    await rm(this.#filename(namespace, assertSecretName(name)), { force: true });
  }

  async deleteNamespace(namespace: string): Promise<void> {
    await rm(this.#directory(namespace), { recursive: true, force: true });
  }

  #directory(namespace: string): string {
    if (!/^[A-Za-z0-9_-]{1,512}$/.test(namespace)) throw new Error('INVALID_VAULT_NAMESPACE');
    return path.join(this.#root, namespace);
  }

  #filename(namespace: string, name: string): string {
    const digest = createHash('sha256').update(name, 'utf8').digest('hex');
    return path.join(this.#directory(namespace), `${digest}.json`);
  }
}
