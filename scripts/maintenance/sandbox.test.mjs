import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { commandEnv, readableDirs, sandboxed } from './sandbox.mjs';

test('commandEnv drops credentials and keeps pnpm from installing before scripts', () => {
  const env = commandEnv({
    PATH: '/usr/bin', HOME: '/home/runner', OPENROUTER_API_KEY: 'k', GH_TOKEN: 't', ACTIONS_RUNTIME_TOKEN: 'r',
    GITHUB_ENV: '/tmp/env', DATABASE_PASSWORD: 'p', NPM_CONFIG_SECRET: 's',
  });
  assert.deepEqual(env, {
    PATH: '/usr/bin', HOME: '/home/runner', CI: 'true', pnpm_config_verify_deps_before_run: 'false',
  });
});

const argsOf = (options) => sandboxed('/home/runner/work/repo', 'pnpm', ['test'], { home: '/home/runner', ...options })[1];
const pairs = (args, flag) => args.flatMap((arg, i) => (arg === flag ? [[args[i + 1], args[i + 2]]] : []));

test('sandboxed hides the home directory, /tmp and /run, and keeps .git read-only', () => {
  const [file, args] = sandboxed('/home/runner/work/repo', 'pnpm', ['test'], { home: '/home/runner', readable: ['/home/runner/setup-pnpm'] });
  assert.equal(file, 'bwrap');
  assert.deepEqual(args.slice(0, 6), ['--ro-bind', '/', '/', '--dev', '/dev', '--proc']);
  assert.deepEqual(args.filter((arg, i) => args[i - 1] === '--tmpfs'), ['/tmp', '/run', '/home/runner']);
  // Later mounts win, so what is reopened comes after what is hidden.
  const order = (path) => args.lastIndexOf(path);
  assert.ok(order('/home/runner') < order('/home/runner/setup-pnpm'));
  assert.ok(order('/home/runner/setup-pnpm') < order('/home/runner/work/repo'));
  assert.deepEqual(pairs(args, '--ro-bind'), [['/', '/'], ['/home/runner/setup-pnpm', '/home/runner/setup-pnpm']]);
  assert.deepEqual(pairs(args, '--bind'), [['/home/runner/work/repo', '/home/runner/work/repo']]);
  assert.deepEqual(pairs(args, '--ro-bind-try'), [['/home/runner/work/repo/.git', '/home/runner/work/repo/.git']]);
  assert.deepEqual(args.slice(args.indexOf('--')), ['--', 'pnpm', 'test']);
});

test('sandboxed cuts the network and further user namespaces unless the network is asked for', () => {
  const offline = argsOf({});
  for (const flag of ['--unshare-all', '--unshare-user', '--disable-userns', '--die-with-parent', '--new-session']) {
    assert.ok(offline.includes(flag), flag);
  }
  assert.ok(!offline.includes('--share-net'));
  assert.ok(argsOf({ network: true }).includes('--share-net'));
});

test('sandboxed makes only the given directories writable besides the repository', () => {
  const args = argsOf({ writable: ['/home/runner/setup-pnpm/node_modules/.bin/store'] });
  assert.deepEqual(pairs(args, '--bind').map(([path]) => path), [
    '/home/runner/work/repo', '/home/runner/setup-pnpm/node_modules/.bin/store',
  ]);
});

test('readableDirs reopens the tools found in the hidden areas and the git directory of a worktree', () => {
  const home = mkdtempSync(join(tmpdir(), 'sandbox-home-'));
  mkdirSync(join(home, 'setup-pnpm/node_modules/pnpm/bin'), { recursive: true });
  mkdirSync(join(home, 'setup-pnpm/node_modules/.bin'), { recursive: true });
  writeFileSync(join(home, 'setup-pnpm/node_modules/pnpm/bin/pnpm.mjs'), '');
  symlinkSync('../pnpm/bin/pnpm.mjs', join(home, 'setup-pnpm/node_modules/.bin/pnpm'));
  const repo = join(home, 'work/repo');
  mkdirSync(join(home, 'main/.git/worktrees/repo'), { recursive: true });
  mkdirSync(repo, { recursive: true });
  writeFileSync(join(repo, '.git'), `gitdir: ${join(home, 'main/.git/worktrees/repo')}\n`);
  writeFileSync(join(home, 'main/.git/worktrees/repo/commondir'), '../..\n');

  const options = { home, areas: [home], env: { PATH: join(home, 'setup-pnpm/node_modules/.bin') } };
  assert.deepEqual(readableDirs(repo, options), [
    join(home, 'setup-pnpm'), join(home, 'main/.git/worktrees/repo'), join(home, 'main/.git'),
  ]);
  assert.throws(() => readableDirs(repo, { ...options, env: { PATH: '' } }), /pnpm is not on PATH/);

  // dirdoc is reopened too when it is installed there.
  mkdirSync(join(home, 'go/bin'), { recursive: true });
  writeFileSync(join(home, 'go/bin/dirdoc'), '');
  const withDirdoc = { ...options, env: { PATH: [join(home, 'setup-pnpm/node_modules/.bin'), join(home, 'go/bin')].join(':') } };
  assert.ok(readableDirs(repo, withDirdoc).includes(join(home, 'go')));
});
