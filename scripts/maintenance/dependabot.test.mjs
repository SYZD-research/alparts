import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIncorporated } from './dependabot.mjs';

const script = fileURLToPath(new URL('./dependabot.mjs', import.meta.url));

test('isIncorporated needs every change in the final manifests', () => {
  const changes = [
    { path: 'package.json', section: 'devDependencies', name: 'oxlint', to: '1.88.0' },
    { path: 'packages/server/package.json', section: 'dependencies', name: 'express', to: null },
  ];
  const final = {
    'package.json': { devDependencies: { oxlint: '1.88.0' } },
    'packages/server/package.json': { dependencies: {} },
  };
  assert.equal(isIncorporated(changes, (path) => final[path]), true);
  final['package.json'].devDependencies.oxlint = '1.87.0';
  assert.equal(isIncorporated(changes, (path) => final[path]), false);
  assert.equal(isIncorporated([], () => ({})), false);
});

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'dependabot-test-'));
  const env = {
    ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid',
    GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid',
  };
  const git = (...args) => execFileSync('git', args, { cwd: dir, env, encoding: 'utf8' });
  const write = (path, value) => writeFileSync(join(dir, path), typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
  const cli = (...args) => spawnSync(process.execPath, [script, ...args], { cwd: dir, env, encoding: 'utf8' });
  git('init', '-q', '-b', 'master');
  write('package.json', { name: 'root', devDependencies: { oxlint: '1.87.0' } });
  write('pnpm-lock.yaml', 'lockfileVersion: 9.0\n');
  git('add', '-A');
  git('commit', '-qm', 'base');
  return { dir, git, write, cli, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// Creates a branch from master with the given change and stores it where the
// workflow keeps fetched pull requests.
function pullRequest(r, number, change) {
  r.git('switch', '-q', '-c', `pr-${number}`, 'master');
  change();
  r.git('add', '-A');
  r.git('commit', '-qm', `pr ${number}`);
  r.git('update-ref', `refs/maintenance/pr/${number}`, 'HEAD');
  r.git('switch', '-q', 'master');
}

test('validate accepts version bumps and refuses anything else', (t) => {
  const r = repo();
  t.after(r.cleanup);
  pullRequest(r, 1, () => {
    r.write('package.json', { name: 'root', devDependencies: { oxlint: '1.88.0' } });
    r.write('pnpm-lock.yaml', 'lockfileVersion: 9.0\n# updated\n');
  });
  pullRequest(r, 2, () => r.write('pnpm-lock.yaml', 'lockfileVersion: 9.0\n# transitive only\n'));
  pullRequest(r, 3, () => {
    r.write('package.json', { name: 'root', scripts: { postinstall: 'x' }, devDependencies: { oxlint: '1.88.0' } });
  });
  pullRequest(r, 4, () => r.write('Dockerfile', 'FROM node:26\n'));

  assert.equal(r.cli('validate', '1').status, 0);
  const lockOnly = r.cli('validate', '2');
  assert.equal(lockOnly.status, 1);
  assert.match(lockOnly.stderr, /changes no dependency versions/);
  assert.match(r.cli('validate', '3').stderr, /"scripts" changed/);
  assert.match(r.cli('validate', '4').stderr, /changes Dockerfile/);
});

test('incorporated lists the pull requests whose changes are all staged', (t) => {
  const r = repo();
  t.after(r.cleanup);
  pullRequest(r, 7, () => r.write('package.json', { name: 'root', devDependencies: { oxlint: '1.88.0' } }));
  pullRequest(r, 8, () => r.write('package.json', { name: 'root', devDependencies: { oxlint: '1.89.0' } }));

  r.write('package.json', { name: 'root', devDependencies: { oxlint: '1.88.0' } });
  r.git('add', 'package.json');
  assert.equal(r.cli('incorporated', '7', '8').stdout.trim(), '7');
  assert.equal(r.cli('incorporated').stdout.trim(), '');
});
