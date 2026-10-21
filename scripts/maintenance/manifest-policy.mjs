// Rules for package.json changes made by the dependency maintenance run: an
// existing dependency from the registry may move to another version or be
// removed, and nothing else in the manifest may change. New dependencies,
// scripts and settings always need a person.

import { execFileSync } from 'node:child_process';

export const DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

// The versions a dependency may move to or from: an exact version, or a caret
// or tilde range on one. A URL, a git or file reference, an npm: alias or a
// workspace reference would install other code than the named package. Checks
// in the agent job run code the model wrote and can edit the manifests, so
// the publish job enforces this with the copy from the base commit.
export const VERSION_SPEC = /^[\^~]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

const isVersion = (spec) => typeof spec === 'string' && VERSION_SPEC.test(spec);
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

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
    if (!isObject(to)) {
      violations.push(`"${section}" is not an object`);
      continue;
    }
    for (const name of new Set([...Object.keys(from), ...Object.keys(to)])) {
      if (from[name] === to[name]) continue;
      if (!Object.hasOwn(from, name)) {
        violations.push(`${section}.${name} added`);
      } else if (!isVersion(from[name])) {
        violations.push(`${section}.${name} is ${JSON.stringify(from[name])}, which only a person may change`);
      } else if (Object.hasOwn(to, name) && !isVersion(to[name])) {
        violations.push(`${section}.${name} set to ${JSON.stringify(to[name])}, which is not a version`);
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
  if (!isObject(after)) return [`${path} is not an object`];
  return manifestChanges(before, after).violations.map((violation) => `${path}: ${violation}`);
}
