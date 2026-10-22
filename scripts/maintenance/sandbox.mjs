// Runs the maintenance agent's commands with bubblewrap, away from what the
// job holds. Checks run code the model wrote, and installs run code from the
// registry, while the agent process and the runner hold the OpenRouter key
// and later steps run with more trust. So each command gets its own user,
// PID and IPC namespaces, and its own network namespace unless it needs the
// registry. It sees no other process, no sockets in /run (Docker's included)
// and none of the home directory except the tools, and the file system is
// read-only apart from the repository (not its .git), a private /tmp and the
// directories given. It cannot gain privileges or create user namespaces.
//
//   node sandbox.mjs [--network] [--writable <dir>]... -- <command> [args...]
//
// runs a command in the working directory, which must be the repository
// root. The agent uses sandboxed() for the same.

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

// Credentials stay out of the command's environment too. pnpm would
// otherwise install before running a script whenever it thinks node_modules
// is stale, which needs the network.
export function commandEnv(env = process.env) {
  const result = { ...env, CI: 'true', pnpm_config_verify_deps_before_run: 'false' };
  for (const name of Object.keys(result)) {
    if (/TOKEN|SECRET|KEY|PASSWORD|^ACTIONS_|^GITHUB_/i.test(name)) delete result[name];
  }
  return result;
}

function onPath(name, env) {
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    const file = join(dir, name);
    if (dir && existsSync(file)) return file;
  }
  throw new Error(`${name} is not on PATH`);
}

// Null when there is no such file or it is a directory.
function readTextFile(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'EISDIR') return null;
    throw error;
  }
}

// The directories outside the repository that the command reads from the
// hidden areas: the top directory there of node and pnpm (both the
// command and its real path), and the git directory of a worktree.
export function readableDirs(root, { env = process.env, home = homedir(), areas = [home, '/tmp'] } = {}) {
  const dirs = new Set();
  for (const file of [process.execPath, onPath('pnpm', env)]) {
    for (const path of [file, realpathSync(file)]) {
      for (const area of areas) {
        const rel = relative(area, path);
        if (rel && !rel.startsWith('..') && !isAbsolute(rel)) dirs.add(join(area, rel.split(sep)[0]));
      }
    }
  }
  // In a worktree, .git is a file that names the git directory.
  const gitDirLine = readTextFile(join(root, '.git'))?.match(/^gitdir: (.+)$/m);
  if (gitDirLine) {
    const gitDir = resolve(root, gitDirLine[1]);
    dirs.add(gitDir);
    const common = readTextFile(join(gitDir, 'commondir'));
    if (common !== null) dirs.add(resolve(gitDir, common.trim()));
  }
  return [...dirs];
}

function resolvConfInRun() {
  try {
    const target = realpathSync('/etc/resolv.conf');
    return target.startsWith('/run/') ? [target] : [];
  } catch {
    return [];
  }
}

export function sandboxed(root, command, args, { network = false, writable = [], readable = [], home = homedir() } = {}) {
  // With the network, name lookups need resolv.conf, which Ubuntu links into /run.
  const lookups = network ? resolvConfInRun() : [];
  return ['bwrap', [
    '--ro-bind', '/', '/',
    '--dev', '/dev',
    '--proc', '/proc',
    '--tmpfs', '/tmp',
    '--tmpfs', '/run',
    '--tmpfs', home,
    ...[...readable, ...lookups].flatMap((path) => ['--ro-bind', path, path]),
    '--bind', root, root,
    '--ro-bind-try', join(root, '.git'), join(root, '.git'),
    ...writable.flatMap((dir) => ['--bind', dir, dir]),
    '--unshare-all', '--unshare-user', '--disable-userns',
    ...(network ? ['--share-net'] : []),
    '--die-with-parent', '--new-session',
    '--chdir', root,
    '--', command, ...args,
  ]];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { network: { type: 'boolean' }, writable: { type: 'string', multiple: true } },
  });
  if (positionals.length === 0) {
    console.error('usage: sandbox.mjs [--network] [--writable <dir>]... -- <command> [args...]');
    process.exit(2);
  }
  const root = process.cwd();
  const [file, args] = sandboxed(root, positionals[0], positionals.slice(1), {
    network: values.network,
    writable: (values.writable ?? []).map((dir) => resolve(dir)),
    readable: readableDirs(root),
  });
  const result = spawnSync(file, args, { stdio: 'inherit', env: commandEnv() });
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}
