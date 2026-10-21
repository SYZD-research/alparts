import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalUuid } from './canonical-id.js';
import { mlsGroupCommit, mlsMemberPackageRequest } from '../routes/mls-schema.js';

const capital = (id: string) => id.toUpperCase();
const oneCapital = (id: string) => id.replace(/[a-f]/, (letter) => letter.toUpperCase());
const signature = () => randomBytes(64).toString('base64');

describe('ids from clients', () => {
  it('accepts only the lowercase form of an id', () => {
    const id = randomUUID();
    assert.equal(canonicalUuid.safeParse(id).success, true);
    for (const other of [capital(id), oneCapital(id), `${id} `, id.replaceAll('-', '')]) {
      assert.equal(canonicalUuid.safeParse(other).success, false, other);
    }
  });

  it('refuses an id in another letter case anywhere in a signed group package or commit', () => {
    // Signatures cover ids as sent, while PostgreSQL hands them back in
    // lowercase, so an id in capitals would no longer match its signature.
    const id = () => `a${randomUUID().slice(1)}`;
    const pkg = { packageId: id(), keyPackage: 'AAAA', signature: signature() };
    assert.equal(mlsMemberPackageRequest.safeParse(pkg).success, true);
    assert.equal(mlsMemberPackageRequest.safeParse({ ...pkg, packageId: capital(pkg.packageId) }).success, false);

    const commit = {
      channelId: id(),
      version: 2,
      previousVersion: 1,
      previousTranscript: 'a'.repeat(64),
      groupId: 'group',
      epoch: 1,
      kind: 'commit',
      keyCommitment: 'A'.repeat(43),
      commit: 'AAAA',
      welcome: '',
      added: [{ ...pkg, deviceId: id(), userId: id(), identityKey: '{}' }],
      removed: [id()],
      members: [{ deviceId: id(), userId: id(), leafIndex: 0 }],
      directoryHeads: [{ userId: id(), sequence: 1, hash: 'b'.repeat(64) }],
      committerDeviceId: id(),
      signature: signature(),
    };
    assert.equal(mlsGroupCommit.safeParse(commit).success, true);
    const variants: Array<(value: typeof commit) => unknown> = [
      (value) => ({ ...value, channelId: capital(value.channelId) }),
      (value) => ({ ...value, committerDeviceId: capital(value.committerDeviceId) }),
      (value) => ({ ...value, removed: value.removed.map(capital) }),
      (value) => ({ ...value, added: value.added.map((entry) => ({ ...entry, packageId: capital(entry.packageId) })) }),
      (value) => ({ ...value, added: value.added.map((entry) => ({ ...entry, deviceId: capital(entry.deviceId) })) }),
      (value) => ({ ...value, added: value.added.map((entry) => ({ ...entry, userId: capital(entry.userId) })) }),
      (value) => ({ ...value, members: value.members.map((member) => ({ ...member, deviceId: capital(member.deviceId) })) }),
      (value) => ({ ...value, members: value.members.map((member) => ({ ...member, userId: capital(member.userId) })) }),
      (value) => ({ ...value, directoryHeads: value.directoryHeads.map((head) => ({ ...head, userId: capital(head.userId) })) }),
    ];
    for (const [index, variant] of variants.entries()) {
      assert.equal(mlsGroupCommit.safeParse(variant(commit)).success, false, `variant ${index}`);
    }
  });

  it('validates every id that requests and socket events carry with canonicalUuid', async () => {
    // z.string().uuid() accepts any letter case.
    const root = fileURLToPath(new URL('..', import.meta.url));
    const found: string[] = [];
    for (const directory of ['routes', 'websocket', 'middleware']) {
      for (const name of await readdir(join(root, directory), { recursive: true })) {
        if (!name.endsWith('.ts') || name.endsWith('.test.ts')) continue;
        const text = await readFile(join(root, directory, name), 'utf8');
        if (/\.uuid\(/.test(text)) found.push(`${directory}/${name}`);
      }
    }
    assert.deepEqual(found, []);
  });
});
