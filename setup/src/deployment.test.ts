import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createServer as createTlsServer } from 'node:tls';
import type { Context } from './context.ts';
import { backupScheduled, carriesCurrentPin, changeableByOthers, probeProxy, sourceVersion, stableNodePath } from './deployment.ts';
import { RunLog } from './log.ts';
import { systemPaths } from './paths.ts';
import { createRunner, type RunResult } from './run.ts';
import type { Settings } from './settings.ts';
import { createCertificateAuthority, issueServerCertificate, type IssuedCertificate } from './x509.ts';

const domain = 'chat.example.com';

function settings(certificates: Settings['certificates']): Settings {
  return {
    version: 1,
    language: 'en',
    domain,
    acmeEmail: null,
    certificates,
    email: { mode: 'disabled' },
    voice: { relay: false, publicAddress: null, basePort: 40000, workers: 1 },
    backup: null,
    network: { edgeSubnet: '10.199.73.0/28', proxyAddress: '10.199.73.2', appPort: 3000 },
    image: { tag: 'abc123', previousTag: null },
    auditHeadObjectKey: 'alparts-0123',
    state: { audit: 'initialized', completed: true, createdAt: '2026-10-27T00:00:00.000Z' },
  };
}

/** A context whose proxy holds `authority` as the authority of its `local` certificates. */
function proxyHolding(authority: string | null): Context {
  const exec = async () => (authority ? { code: 0, stdout: authority, stderr: '' } : { code: 1, stdout: '', stderr: '' });
  return { docker: { exec } } as unknown as Context;
}

/** A stand-in for the proxy that serves `certificate` and answers the first request with `answer`. */
async function withProxy(certificate: IssuedCertificate, answer: string, probe: (port: number, requests: string[]) => Promise<void>): Promise<void> {
  const requests: string[] = [];
  const server = createTlsServer({ key: certificate.privateKeyPem, cert: certificate.certificatePem }, (socket) => {
    socket.once('data', (request: Buffer) => {
      requests.push(request.toString('latin1'));
      socket.end(answer);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await probe((server.address() as AddressInfo).port, requests);
  } finally {
    server.close();
  }
}

test('the proxy check verifies the certificate for the domain before it asks for the app', async () => {
  const authority = createCertificateAuthority('Caddy Local Authority', 30);
  const stranger = createCertificateAuthority('Somebody else', 30);
  const valid = issueServerCertificate(authority, { commonName: domain, dnsNames: [domain], validDays: 30 });
  const ok = 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';

  await withProxy(valid, ok, async (port, requests) => {
    const answer = await probeProxy(proxyHolding(authority.certificatePem), settings('local'), port);
    assert.equal(answer?.status, 200);
    assert.ok(answer?.certificate.checkHost(domain));
    assert.match(requests[0] ?? '', /^GET \/ HTTP\/1\.1\r\nHost: chat\.example\.com\r\n/);
    // Not trusted by the public authorities, and nothing to trust without the proxy's own.
    assert.equal(await probeProxy(proxyHolding(authority.certificatePem), settings('public'), port), null);
    assert.equal(await probeProxy(proxyHolding(null), settings('local'), port), null);
  });
  await withProxy(valid, 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n', async (port) => {
    const answer = await probeProxy(proxyHolding(authority.certificatePem), settings('local'), port);
    assert.equal(answer?.status, 502);
  });
  const wrongName = issueServerCertificate(authority, { commonName: 'other.example.com', dnsNames: ['other.example.com'], validDays: 30 });
  await withProxy(wrongName, ok, async (port) => {
    assert.equal(await probeProxy(proxyHolding(authority.certificatePem), settings('local'), port), null);
  });
  const wrongAuthority = issueServerCertificate(stranger, { commonName: domain, dnsNames: [domain], validDays: 30 });
  await withProxy(wrongAuthority, ok, async (port) => {
    assert.equal(await probeProxy(proxyHolding(authority.certificatePem), settings('local'), port), null);
  });
});

test('a certificate passes for the pins file only with the current key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-pins-'));
  try {
    const authority = createCertificateAuthority('Caddy Local Authority', 30);
    const [current, spare, other] = [0, 1, 2].map(() => issueServerCertificate(authority, { commonName: domain, dnsNames: [domain], validDays: 30 }));
    writeFileSync(join(dir, 'proxy_tls_current_key'), current!.privateKeyPem);
    writeFileSync(join(dir, 'proxy_tls_spare_key'), spare!.privateKeyPem);
    const context = { paths: { secretsDir: dir } } as unknown as Context;
    assert.ok(carriesCurrentPin(context, new X509Certificate(current!.certificatePem)));
    // The spare is for after a switch: until then the proxy serves the current key.
    assert.ok(!carriesCurrentPin(context, new X509Certificate(spare!.certificatePem)));
    assert.ok(!carriesCurrentPin(context, new X509Certificate(other!.certificatePem)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the image tag changes with untracked files, and stays for the same source', async () => {
  const repo = mkdtempSync(join(tmpdir(), 'alparts-source-'));
  try {
    const run = createRunner(new RunLog(null, 'test'));
    const git = (...args: string[]) => run('git', ['-C', repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false', ...args]);
    await git('init', '--quiet');
    writeFileSync(join(repo, 'tracked.txt'), 'one');
    await git('add', 'tracked.txt');
    await git('commit', '--quiet', '-m', 'first');
    const context = { run, paths: { repo } } as unknown as Context;
    const commit = (await sourceVersion(context)).tag;
    assert.match(commit, /^[0-9a-f]{12}$/);

    const added = join(repo, 'added.txt');
    writeFileSync(added, 'first');
    const first = await sourceVersion(context);
    writeFileSync(added, 'second');
    const second = await sourceVersion(context);
    assert.ok(first.dirty && second.dirty);
    assert.ok(first.tag.startsWith(`${commit}-local-`));
    assert.notEqual(first.tag, second.tag);
    assert.equal((await sourceVersion(context)).tag, second.tag);

    // A tracked file counts by what it holds now, however large.
    const tracked = join(repo, 'tracked.txt');
    writeFileSync(tracked, `a${'x'.repeat(5 * 1024 * 1024)}`);
    const third = await sourceVersion(context);
    writeFileSync(tracked, `b${'x'.repeat(5 * 1024 * 1024)}`);
    assert.notEqual((await sourceVersion(context)).tag, third.tag);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test('the daily backups count as scheduled only while systemd has the timer enabled and running', async () => {
  const root = mkdtempSync(join(tmpdir(), 'alparts-units-'));
  try {
    const paths = systemPaths(root, '/opt/alparts');
    const answers = new Map<string, number>([['is-enabled', 0], ['is-active', 0]]);
    const run = async (command: string, args: string[]): Promise<RunResult> => ({ code: command === 'systemctl' ? answers.get(args[0]!) ?? 1 : 1, stdout: '', stderr: '' });
    const context = { run, paths } as unknown as Context;
    assert.equal(await backupScheduled(context), false);
    mkdirSync(paths.systemdDir, { recursive: true });
    writeFileSync(join(paths.systemdDir, 'alparts-production-backup.timer'), '');
    assert.equal(await backupScheduled(context), true);
    // The unit files stay when enabling them failed.
    answers.set('is-enabled', 1);
    assert.equal(await backupScheduled(context), false);
    answers.set('is-enabled', 0).set('is-active', 3);
    assert.equal(await backupScheduled(context), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('the backup timer names a Node.js that a snap refresh keeps', () => {
  assert.equal(stableNodePath('/snap/node/10251/bin/node'), '/snap/node/current/bin/node');
  assert.equal(stableNodePath('/snap/node/x2/bin/node'), '/snap/node/current/bin/node');
  assert.equal(stableNodePath('/usr/bin/node'), '/usr/bin/node');
});

test('what the root timer runs must be out of reach of other users', () => {
  // System files and every directory above them belong to root.
  assert.equal(changeableByOthers(['/usr/bin/env'], []), null);
  const dir = mkdtempSync(join(tmpdir(), 'alparts-tree-'));
  try {
    const open = join(dir, 'open');
    writeFileSync(open, '');
    chmodSync(open, 0o666);
    assert.equal(changeableByOthers([open], []), open);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a tree is refused for a symbolic link anywhere in it, but not in node_modules', { skip: process.getuid?.() !== 0 && 'needs files owned by root' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-tree-'));
  try {
    mkdirSync(join(dir, 'src', 'node_modules'), { recursive: true });
    writeFileSync(join(dir, 'src', 'main.ts'), '');
    symlinkSync('/tmp', join(dir, 'src', 'node_modules', 'link'));
    assert.equal(changeableByOthers([], [dir]), null);
    symlinkSync('/tmp', join(dir, 'src', 'link'));
    assert.equal(changeableByOthers([], [dir]), join(dir, 'src', 'link'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
