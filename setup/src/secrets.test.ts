import assert from 'node:assert/strict';
import { createHash, createHmac, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { backupServiceFile, databaseUrl, GENERATED_SECRETS, scramSha256Verifier, SecretStore, storageIdentities } from './secrets.ts';
import type { Settings } from './settings.ts';

test('the SCRAM verifier reproduces the RFC 7677 exchange', () => {
  const verifier = scramSha256Verifier('pencil', Buffer.from('W22ZaJ0SNY7soEsUEjb6gQ==', 'base64'), 4096);
  const match = /^SCRAM-SHA-256\$4096:([^$]+)\$([^:]+):(.+)$/.exec(verifier);
  assert.ok(match);
  const storedKey = Buffer.from(match[2]!, 'base64');
  const serverKey = Buffer.from(match[3]!, 'base64');
  const authMessage = 'n=user,r=rOprNGfwEbeRWgbNEkqO,'
    + 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,'
    + 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0';
  assert.equal(createHmac('sha256', serverKey).update(authMessage).digest('base64'), '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=');
  // The client proof XORed with the client signature gives the client key, whose hash is the stored key.
  const clientSignature = createHmac('sha256', storedKey).update(authMessage).digest();
  const proof = Buffer.from('dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=', 'base64');
  const clientKey = Buffer.from(proof.map((byte, index) => byte ^ clientSignature[index]!));
  assert.deepEqual(createHash('sha256').update(clientKey).digest(), storedKey);
});

test('connection settings escape passwords, and the backup role verifies the server and only reads', () => {
  const text = databaseUrl('alparts_app', 'a/b');
  assert.ok(text.endsWith('\n'));
  const url = new URL(text.trim());
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.username, 'alparts_app');
  assert.equal(url.password, 'a%2Fb');
  assert.equal(url.host, 'postgres:5432');
  assert.equal(url.pathname, '/alparts');
  assert.equal(url.search, '');
  const service = backupServiceFile('pw');
  assert.match(service, /^\[alparts_backup\]\n/);
  assert.match(service, /\nsslmode=verify-full\n/);
  assert.match(service, /\nuser=alparts_backup\n/);
  const identities = JSON.parse(storageIdentities({ admin: ['a', 'b'], app: ['c', 'd'], backup: ['e', 'f'] }));
  const byName = Object.fromEntries(identities.identities.map((identity: { name: string; actions: string[] }) => [identity.name, identity.actions]));
  assert.deepEqual(byName['alparts-backup'], ['Read:alparts', 'List:alparts']);
  assert.ok(!byName['alparts-app'].includes('Admin'));
  assert.ok(byName['alparts-app'].includes('Write:alparts-audit'));
});

function settings(): Settings {
  return {
    version: 1,
    language: 'en',
    domain: 'chat.example.com',
    acmeEmail: null,
    certificates: 'public',
    email: { mode: 'disabled' },
    voice: { relay: false, publicAddress: null, basePort: 40000, workers: 1 },
    backup: null,
    network: { edgeSubnet: '172.30.233.0/28', proxyAddress: '172.30.233.2', appPort: 3000 },
    image: { tag: null, previousTag: null },
    auditHeadObjectKey: 'alparts-test',
    state: { audit: 'none', completed: false, createdAt: '2026-10-27T00:00:00.000Z' },
  };
}

test('generated values are created once, private, and never replaced', () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-secrets-'));
  try {
    const store = new SecretStore(join(dir, 'secrets'));
    const created = store.ensureGenerated();
    assert.deepEqual(new Set(created), new Set(Object.keys(GENERATED_SECRETS)));
    assert.equal(statSync(store.dir).mode & 0o777, 0o700);
    const pepper = store.read('password_pepper');
    assert.match(pepper, /^[0-9a-f]{96}$/);
    assert.equal(statSync(store.path('password_pepper')).mode & 0o777, 0o400);
    assert.deepEqual(store.ensureGenerated(), []);
    assert.equal(store.read('password_pepper'), pepper);

    store.writeDerivedFiles(settings());
    assert.equal(store.read('database_url'), `postgresql://alparts_app:${store.read('postgres_app_password')}@postgres:5432/alparts`);
    const ca = new X509Certificate(readFileSync(store.path('internal_ca_certificate')));
    const postgres = new X509Certificate(readFileSync(store.path('postgres_tls_certificate')));
    assert.ok(postgres.checkIssued(ca));
    assert.equal(postgres.checkHost('postgres'), 'postgres');
    assert.equal(store.read('empty'), '');

    // A second run keeps the certificates that are still good.
    const before = readFileSync(store.path('storage_tls_certificate'), 'utf8');
    store.writeDerivedFiles(settings());
    assert.equal(readFileSync(store.path('storage_tls_certificate'), 'utf8'), before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
