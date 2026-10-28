import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { isAgeRecipient, isEmailAddress, isPrivateIPv4, loadSettings, normalizeDomain, normalizeTime, parseSettings, saveSettings, type Settings } from './settings.ts';

const valid: Settings = {
  version: 1,
  language: 'ja',
  domain: 'chat.example.com',
  acmeEmail: null,
  certificates: 'public',
  email: { mode: 'smtp', host: 'smtp.example.com', port: 587, security: 'starttls', from: 'no-reply@example.com', user: null },
  voice: { relay: true, publicAddress: '203.0.113.10', basePort: 40000, workers: 1 },
  backup: { recipient: 'age1pq1qqqq', time: '04:00', retentionDays: 30, minimumCopies: 7 },
  network: { edgeSubnet: '10.199.73.0/28', proxyAddress: '10.199.73.2', appPort: 3000 },
  image: { tag: '1c9e856f2fa6', previousTag: null },
  auditHeadObjectKey: 'alparts-0123',
  state: { audit: 'initialized', completed: true, createdAt: '2026-10-27T00:00:00.000Z' },
};

test('domain names are normalized to lower-case ASCII and malformed ones refused', () => {
  assert.equal(normalizeDomain(' Chat.Example.COM. '), 'chat.example.com');
  assert.equal(normalizeDomain('チャット.例え.jp'), 'xn--7ckep0i.xn--r8jz45g.jp');
  for (const bad of ['localhost', '203.0.113.10', 'https://chat.example.com', 'chat.example.com:443', '-bad.example.com', 'a..b', 'example.123', '']) {
    assert.equal(normalizeDomain(bad), null, bad);
  }
});

test('addresses, keys and times are checked the way the server and backup scripts check them', () => {
  assert.ok(isEmailAddress('no-reply@example.com'));
  assert.ok(!isEmailAddress('Alparts <no-reply@example.com>'));
  assert.ok(isPrivateIPv4('192.168.1.10') && isPrivateIPv4('10.0.0.1') && isPrivateIPv4('100.64.1.1'));
  assert.ok(!isPrivateIPv4('203.0.113.10'));
  assert.ok(isAgeRecipient('age1pq1qyqszqgpqyqszqgpqyqszqgp'));
  assert.ok(!isAgeRecipient('age1qyqszqgpqyqszqgp'));
  assert.ok(!isAgeRecipient('AGE-SECRET-KEY-1ABC'));
  assert.equal(normalizeTime('4:05'), '04:05');
  assert.equal(normalizeTime('24:00'), null);
});

test('saved settings read back, and edits that would break the deployment are refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-settings-'));
  try {
    const file = join(dir, 'config', 'setup.json');
    assert.equal(loadSettings(file), null);
    saveSettings(file, valid);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, 'config')).mode & 0o777, 0o700);
    assert.deepEqual(loadSettings(file), valid);

    const edited = join(dir, 'edited.json');
    writeFileSync(edited, JSON.stringify({ ...valid, domain: 'not a domain' }));
    assert.throws(() => loadSettings(edited), /domain/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const broken: Array<[string, unknown]> = [
    ['voice.publicAddress', { ...valid, voice: { ...valid.voice, publicAddress: null } }],
    ['email.port', { ...valid, email: { ...valid.email, port: 0 } }],
    ['backup.recipient', { ...valid, backup: { ...valid.backup, recipient: 'AGE-SECRET-KEY-1' } }],
    ['image.tag', { ...valid, image: { tag: 'bad tag', previousTag: null } }],
    ['state.audit', { ...valid, state: { ...valid.state, audit: 'maybe' } }],
    ['network.edgeSubnet', { ...valid, network: { ...valid.network, edgeSubnet: '10.0.0.0/8' } }],
  ];
  for (const [field, value] of broken) assert.throws(() => parseSettings(value), new RegExp(field.replace('.', '\\.')), field);
});
