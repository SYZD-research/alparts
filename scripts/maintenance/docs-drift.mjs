// Finds the dirdoc descriptions that have fallen behind the code, in the
// areas the maintenance agent may change, from the git history: a file
// changed in a later commit than its description, a code file or directory
// without a description, a directory that gained or lost files after its
// description, and the description of a file that is gone. dirdoc check
// cannot see these, because a description does not record the code it was
// written against.
//
//   node docs-drift.mjs [--limit <n>]   prints { items, total } as JSON
//   node docs-drift.mjs --prune         deletes the descriptions of files that are gone
//
// Run from the repository root of a full clone: a shallow one has no history
// to compare.

import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { WRITABLE_PREFIXES, isDocumentationPath, isWritablePath } from './agent.mjs';

// Files expected to have a description of their own. Others, such as JSON,
// SQL and styles, are covered by their directory's tree.
const CODE_FILE = /\.(?:[cm]?[jt]sx?|md)$/;
export const DEFAULT_LIMIT = 20;
// The order the items are listed and taken in.
const KINDS = ['file-changed', 'dir-changed', 'file-missing', 'dir-missing', 'orphan'];

function dirOf(path) {
  const slash = path.lastIndexOf('/');
  return slash < 0 ? '' : path.slice(0, slash);
}

export function fileDocPath(path) {
  return `${dirOf(path)}/.dirdoc/${path.slice(path.lastIndexOf('/') + 1)}.dirdoc_pfd`;
}

export function dirDocPath(dir) {
  return `${dir}/.dirdoc/.dirdoc_dsd`;
}

// The file a file description describes, or null for a directory's.
function describedFile(docPath) {
  const name = docPath.slice(docPath.lastIndexOf('/') + 1);
  if (!name.endsWith('.dirdoc_pfd') || name.startsWith('.')) return null;
  return `${dirOf(dirOf(docPath))}/${name.slice(0, -'.dirdoc_pfd'.length)}`;
}

// Reads `git log --no-renames --name-status --format=@%ct`, newest first,
// into the time each path last changed and the time each directory last
// gained or lost a file. Quoted paths (with unusual characters) are skipped.
export function parseLog(text) {
  const changed = new Map();
  const structure = new Map();
  let time = 0;
  for (const line of text.split('\n')) {
    if (line.startsWith('@')) {
      time = Number(line.slice(1));
      continue;
    }
    const [status, path] = line.split('\t');
    if (!path || path.startsWith('"')) continue;
    if (!changed.has(path)) changed.set(path, time);
    const dir = dirOf(path);
    if ((status === 'A' || status === 'D') && !structure.has(dir)) structure.set(dir, time);
  }
  return { changed, structure };
}

function inWritableArea(dir) {
  return dir !== '' && WRITABLE_PREFIXES.some((prefix) => `${dir}/`.startsWith(prefix));
}

// files are the tracked paths; changed and structure come from parseLog.
export function driftItems(files, { changed, structure }) {
  const tracked = new Set(files);
  const time = (path) => changed.get(path) ?? 0;
  const items = new Map();
  const add = (kind, path) => {
    if (!items.has(path)) items.set(path, { kind, path });
  };

  const dirs = new Set();
  for (const file of files) {
    if (isDocumentationPath(file)) {
      const source = describedFile(file);
      if (source && !tracked.has(source)) add('orphan', file);
      continue;
    }
    if (!isWritablePath(file) || !inWritableArea(dirOf(file))) continue;
    for (let dir = dirOf(file); inWritableArea(dir); dir = dirOf(dir)) dirs.add(dir);
    const doc = fileDocPath(file);
    if (tracked.has(doc)) {
      if (time(file) > time(doc)) add('file-changed', file);
    } else if (CODE_FILE.test(file)) {
      add('file-missing', file);
    }
  }
  for (const dir of [...dirs].sort()) {
    const doc = dirDocPath(dir);
    if (!tracked.has(doc)) {
      add('dir-missing', `${dir}/`);
      // Its parent's tree does not list it yet.
      const parent = dirOf(dir);
      if (dirs.has(parent) && tracked.has(dirDocPath(parent))) add('dir-changed', `${parent}/`);
    } else if ((structure.get(dir) ?? 0) > time(doc)) {
      add('dir-changed', `${dir}/`);
    }
  }
  return [...items.values()].sort((a, b) => KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind) || a.path.localeCompare(b.path));
}

const HEADINGS = {
  'file-changed': 'Files whose code changed after their description',
  'dir-changed': 'Directories whose files changed after their description',
  'file-missing': 'Files without a description',
  'dir-missing': 'Directories without a description',
  orphan: 'Descriptions of files that are gone (removed before you started)',
};

export function renderDocsTask(items, total) {
  const lines = ['# dirdoc maintenance', ''];
  for (const kind of KINDS) {
    const paths = items.filter((item) => item.kind === kind).map((item) => item.path);
    if (paths.length) lines.push(`## ${HEADINGS[kind]}`, '', ...paths.map((path) => `- ${path}`), '');
  }
  if (total > items.length) lines.push(`${total - items.length} more items are left for later runs.`, '');
  return `${lines.join('\n')}\n`;
}

function git(args) {
  return execFileSync('git', ['-c', 'core.quotePath=false', ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
}

// Orphans are always taken: removing them needs no model.
export function findDrift({ limit = DEFAULT_LIMIT } = {}) {
  const files = git(['ls-files', '-z']).split('\0').filter(Boolean);
  const log = git(['log', '--no-renames', '--name-status', '--format=@%ct', '--', ...WRITABLE_PREFIXES]);
  const all = driftItems(files, parseLog(log));
  const orphans = all.filter((item) => item.kind === 'orphan');
  const rest = all.filter((item) => item.kind !== 'orphan');
  return { items: [...rest.slice(0, limit), ...orphans], total: all.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { limit: { type: 'string' }, prune: { type: 'boolean' } } });
  const limit = values.limit === undefined ? DEFAULT_LIMIT : Number(values.limit);
  if (!Number.isInteger(limit) || limit < 0) {
    console.error('usage: docs-drift.mjs [--limit <n>] | --prune');
    process.exit(2);
  }
  const drift = findDrift({ limit });
  if (values.prune) {
    for (const { kind, path } of drift.items) {
      if (kind === 'orphan') rmSync(path);
    }
  } else {
    console.log(JSON.stringify(drift));
  }
}
