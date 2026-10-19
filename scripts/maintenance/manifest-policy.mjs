// Rules for package.json changes made by the dependency maintenance run: an
// existing dependency may move to another version or be removed, and nothing
// else in the manifest may change. New dependencies, scripts and settings
// always need a person.

import { execFileSync } from 'node:child_process';

export const DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

// Lists dependency changes between two parsed manifests, and anything that
// breaks the rules above.
export function manifestChanges(before, after) {
  const changes = [];
  const violations = [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const key of keys) {
    if (DEPENDENCY_SECTIONS.includes(key)) continue;
    if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) violations.push(`"${key}" changed`);
  }
  for (const section of DEPENDENCY_SECTIONS) {
    const from = before[section] ?? {};
    const to = after[section] ?? {};
    for (const name of new Set([...Object.keys(from), ...Object.keys(to)])) {
      if (from[name] === to[name]) continue;
      if (!(name in from)) {
        violations.push(`${section}.${name} added`);
      } else {
        changes.push({ section, name, from: from[name], to: to[name] ?? null });
      }
    }
  }
  return { changes, violations };
}

function readManifest(spec) {
  try {
    return JSON.parse(execFileSync('git', ['show', spec], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  } catch {
    return null;
  }
}

// Checks a package.json path staged in the index against its version in HEAD.
export function stagedManifestViolations(path) {
  const before = readManifest(`HEAD:${path}`);
  const after = readManifest(`:${path}`);
  if (!before) return [`${path} is a new manifest`];
  if (!after) return [`${path} was removed`];
  return manifestChanges(before, after).violations.map((violation) => `${path}: ${violation}`);
}
