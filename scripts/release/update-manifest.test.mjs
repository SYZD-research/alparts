import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signManifest, verifyManifest, artifactDigest, verifyArtifacts } from './update-manifest.mjs';

const pair = generateKeyPairSync('ed25519');
const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
const trust = { keys: { release: { publicKey, channels: ['stable'], revoked: false } } };
const now = Date.parse('2026-09-05T00:00:00.000Z');
const options = { channel: 'stable', minimumSequence: 1, now };
const manifest = { version: 1, product: 'alparts', channel: 'stable', sequence: 2,
  issuedAt: '2026-09-04T00:00:00.000Z', expiresAt: '2026-09-06T00:00:00.000Z', commit: 'a'.repeat(40),
  artifacts: [{ name: 'app.apk', size: 3, sha256: 'b'.repeat(64) }] };
test('authenticates manifest and rejects tampering, replay, revoked keys and channel crossover', () => {
  const signed = signManifest(manifest, privatePem, 'release');
  assert.deepEqual(verifyManifest(signed, trust, options), manifest);
  assert.throws(() => verifyManifest({ ...signed, manifest: { ...manifest, sequence: 3 } }, trust, options), /signature/);
  assert.throws(() => verifyManifest(signed, trust, { ...options, minimumSequence: 2 }), /replay/);
  assert.throws(() => verifyManifest(signed, trust, { ...options, now: now + 86400000 }), /Expired/);
  assert.throws(() => verifyManifest(signed, trust, { ...options, channel: 'beta' }), /Untrusted/);
  assert.throws(() => verifyManifest(signed, { keys: { release: { ...trust.keys.release, revoked: true } } }, options), /Untrusted/);
  assert.throws(() => signManifest({ ...manifest, artifacts: [{ ...manifest.artifacts[0], name: '../app.apk' }] }, privatePem, 'release'), /name/);
  assert.throws(() => signManifest({ ...manifest, artifacts: [...manifest.artifacts, ...manifest.artifacts] }, privatePem, 'release'), /Duplicate/);
});
test('checks every artifact byte after signature verification', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'alparts-update-test-'));
  try {
    const filename = join(directory, 'app.apk');
    await writeFile(filename, 'original');
    const value = { ...manifest, artifacts: [await artifactDigest(filename)] };
    await verifyArtifacts(verifyManifest(signManifest(value, privatePem, 'release'), trust, options), directory);
    await writeFile(filename, 'modified');
    await assert.rejects(verifyArtifacts(value, directory), /integrity/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('signs only with a private regular key file, never through a link', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { symlink, chmod } = await import('node:fs/promises');
  const run = (args) => promisify(execFile)(process.execPath, [new URL('./update-manifest.mjs', import.meta.url).pathname, ...args]);
  const directory = await mkdtemp(join(tmpdir(), 'alparts-update-sign-'));
  try {
    const manifestFile = join(directory, 'manifest.json');
    const keyFile = join(directory, 'release.pem');
    await writeFile(manifestFile, JSON.stringify(manifest));
    await writeFile(keyFile, privatePem, { mode: 0o600 });
    await run(['sign', manifestFile, keyFile, 'release', join(directory, 'signed.json')]);
    await symlink(keyFile, join(directory, 'link.pem'));
    await assert.rejects(run(['sign', manifestFile, join(directory, 'link.pem'), 'release', join(directory, 'via-link.json')]));
    await chmod(keyFile, 0o644);
    await assert.rejects(run(['sign', manifestFile, keyFile, 'release', join(directory, 'readable.json')]), /private regular file/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
