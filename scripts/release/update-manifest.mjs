import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { constants } from 'node:fs';
import { lstat, open, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const domain = Buffer.from('alparts-update-manifest-v1\0');
const MAX_DOCUMENT = 256 * 1024;

function assert(condition, message) { if (!condition) throw new Error(message); }
function exactKeys(value, keys) {
  assert(value && typeof value === 'object' && !Array.isArray(value), 'Invalid document');
  assert(Object.keys(value).sort().join(',') === [...keys].sort().join(','), 'Unexpected document fields');
}
export function validateManifest(manifest) {
  exactKeys(manifest, ['version', 'product', 'channel', 'sequence', 'issuedAt', 'expiresAt', 'commit', 'artifacts']);
  assert(manifest.version === 1 && manifest.product === 'alparts', 'Invalid manifest version/product');
  assert(['stable', 'beta', 'development'].includes(manifest.channel), 'Invalid release channel');
  assert(Number.isSafeInteger(manifest.sequence) && manifest.sequence > 0, 'Invalid sequence');
  assert(/^[a-f0-9]{40,64}$/.test(manifest.commit), 'Invalid source commit');
  for (const field of ['issuedAt', 'expiresAt']) {
    assert(typeof manifest[field] === 'string' && Number.isFinite(Date.parse(manifest[field]))
      && new Date(manifest[field]).toISOString() === manifest[field], 'Invalid timestamp');
  }
  assert(Date.parse(manifest.expiresAt) > Date.parse(manifest.issuedAt), 'Invalid expiry');
  assert(Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0 && manifest.artifacts.length <= 64, 'Invalid artifact count');
  const names = new Set();
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, ['name', 'size', 'sha256']);
    assert(typeof artifact.name === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(artifact.name), 'Invalid artifact name');
    assert(!names.has(artifact.name), 'Duplicate artifact'); names.add(artifact.name);
    assert(Number.isSafeInteger(artifact.size) && artifact.size > 0 && artifact.size <= 64 * 1024 ** 3, 'Invalid artifact size');
    assert(typeof artifact.sha256 === 'string' && /^[a-f0-9]{64}$/.test(artifact.sha256), 'Invalid digest');
  }
  return manifest;
}
export function canonicalManifest(manifest) {
  validateManifest(manifest);
  const { version, product, channel, sequence, issuedAt, expiresAt, commit } = manifest;
  return Buffer.from(JSON.stringify({ version, product, channel, sequence, issuedAt, expiresAt, commit,
    artifacts: manifest.artifacts.map(({ name, size, sha256 }) => ({ name, size, sha256 })) }));
}
export function signManifest(manifest, privatePem, keyId) {
  assert(/^[a-z0-9_-]{1,64}$/.test(keyId), 'Invalid key ID');
  const key = createPrivateKey(privatePem);
  assert(key.asymmetricKeyType === 'ed25519', 'An Ed25519 signing key is required');
  const signature = sign(null, Buffer.concat([domain, canonicalManifest(manifest)]), key).toString('base64');
  return { manifest, keyId, signature };
}
export function verifyManifest(envelope, trust, { channel, minimumSequence, now = Date.now() }) {
  exactKeys(envelope, ['manifest', 'keyId', 'signature']);
  assert(Number.isSafeInteger(minimumSequence) && minimumSequence >= 0, 'Invalid trusted sequence');
  const { manifest, keyId, signature } = envelope;
  const canonical = canonicalManifest(manifest);
  const entry = Object.hasOwn(trust.keys, keyId) ? trust.keys[keyId] : undefined;
  assert(entry && !entry.revoked && Array.isArray(entry.channels) && entry.channels.includes(channel), 'Untrusted signing key');
  assert(typeof signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signature), 'Invalid signature encoding');
  const key = createPublicKey(entry.publicKey);
  assert(key.asymmetricKeyType === 'ed25519' && verify(null, Buffer.concat([domain, canonical]), key, Buffer.from(signature, 'base64')), 'Invalid update signature');
  assert(manifest.channel === channel, 'Release channel mismatch');
  assert(manifest.sequence > minimumSequence, 'Rollback or replay rejected');
  assert(Date.parse(manifest.issuedAt) <= now + 300000 && Date.parse(manifest.expiresAt) > now, 'Expired or future update');
  return manifest;
}
export async function artifactDigest(filename) {
  const metadata = await lstat(filename);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), 'Artifact must be a regular file');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return { name: basename(filename), size: metadata.size, sha256: hash.digest('hex') };
}
export async function verifyArtifacts(manifest, directory) {
  validateManifest(manifest);
  for (const artifact of manifest.artifacts) {
    const actual = await artifactDigest(resolve(directory, artifact.name));
    assert(actual.size === artifact.size && actual.sha256 === artifact.sha256, `Artifact integrity failed: ${artifact.name}`);
  }
}
// Check and read the same open file, so it cannot be swapped in between.
async function readCheckedFile(filename, check, flags = constants.O_RDONLY) {
  const handle = await open(filename, flags);
  try {
    check(await handle.stat());
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}
async function readDocument(filename) {
  const contents = await readCheckedFile(filename, (metadata) => assert(metadata.size <= MAX_DOCUMENT, 'Document too large'));
  return JSON.parse(contents.toString('utf8'));
}
async function main(args) {
  const [operation, ...files] = args;
  if (operation === 'sign' && files.length === 4) {
    const [manifestFile, keyFile, keyId, output] = files;
    // O_NOFOLLOW refuses a symbolic link, as the lstat check did.
    const key = await readCheckedFile(keyFile, (metadata) => (
      assert(metadata.isFile() && (metadata.mode & 0o077) === 0, 'Signing key must be a private regular file')
    ), constants.O_RDONLY | constants.O_NOFOLLOW);
    const signed = signManifest(await readDocument(manifestFile), key, keyId);
    await writeFile(output, `${JSON.stringify(signed, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  } else if (operation === 'verify' && files.length === 5) {
    const [manifestFile, trustFile, directory, channel, sequence] = files;
    const manifest = verifyManifest(await readDocument(manifestFile), await readDocument(trustFile), { channel, minimumSequence: Number(sequence) });
    await verifyArtifacts(manifest, directory);
    process.stdout.write(`Verified ${manifest.artifacts.length} artifacts; channel=${manifest.channel}; sequence=${manifest.sequence}\n`);
  } else {
    throw new Error('Usage: update-manifest.mjs sign manifest.json private.pem key-id signed.json | verify signed.json trust.json artifacts-dir channel trusted-sequence');
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
