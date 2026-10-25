// Fails if the staged changes touch a path the maintenance agent must not
// change, or stage anything other than a regular file (a symlink or a
// submodule). Checks run by the agent can write any file, this one included,
// so the jobs after the agent run a copy taken before it started.
//
//   node check-paths.mjs [--allow-manifests] [--allow <path>]... [--docs-only]
//
// --allow-manifests accepts staged package.json changes that only move
// existing registry dependencies to another version or remove them
// (manifest-policy.mjs). --allow accepts one generated file. --docs-only
// accepts nothing but dirdoc descriptions.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { isDocumentationPath, isWritablePath, normalisePath } from './agent.mjs';
import { stagedManifestViolations } from './manifest-policy.mjs';

const REGULAR_FILE = /^100(?:644|755)$/;
const WORKSPACE_MANIFEST = /^(?:packages\/[^/]+\/)?package\.json$/;

// Parses `git diff --cached --raw -z --no-renames` into { mode, path }, with
// mode 000000 for a deleted path.
export function parseRawDiff(text) {
  const fields = text.split('\0');
  const entries = [];
  for (let i = 0; i + 1 < fields.length; i += 2) {
    entries.push({ mode: fields[i].split(' ')[1], path: fields[i + 1] });
  }
  return entries;
}

export function refusedChanges(entries, {
  allowManifests = false, allowed = [], docsOnly = false, manifestViolations = stagedManifestViolations,
} = {}) {
  const refused = [];
  for (const { mode, path } of entries) {
    const rel = normalisePath(path);
    if (!rel) {
      refused.push(path);
    } else if (mode !== '000000' && !REGULAR_FILE.test(mode)) {
      refused.push(`${rel} (not a regular file)`);
    } else if (docsOnly) {
      if (!isDocumentationPath(rel)) refused.push(rel);
    } else if (allowed.includes(rel)) {
      continue;
    } else if (allowManifests && WORKSPACE_MANIFEST.test(rel)) {
      refused.push(...manifestViolations(rel));
    } else if (!isWritablePath(rel)) {
      refused.push(rel);
    }
  }
  return refused;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({
    options: {
      'allow-manifests': { type: 'boolean' }, allow: { type: 'string', multiple: true }, 'docs-only': { type: 'boolean' },
    },
  });
  const diff = execFileSync('git', ['diff', '--cached', '--raw', '-z', '--no-renames', '--no-abbrev'], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  const refused = refusedChanges(parseRawDiff(diff), {
    allowManifests: values['allow-manifests'], allowed: values.allow ?? [], docsOnly: values['docs-only'],
  });
  if (refused.length) {
    console.error(`Changes outside what the maintenance agent may change:\n${refused.join('\n')}`);
    process.exit(1);
  }
}
