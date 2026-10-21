// Reads NUL-separated repository paths from stdin and fails if any of them is
// one the maintenance agent must not change. Checks run by the agent can write
// any file, this one included, so the publish job runs a copy taken from the
// base commit on the final diff.
//
//   node check-paths.mjs [--allow-manifests] [--allow <path>]...
//
// --allow-manifests accepts staged package.json changes that only move
// existing registry dependencies to another version or remove them
// (manifest-policy.mjs). --allow accepts one generated file.

import { parseArgs } from 'node:util';
import { isProtectedPath, normalisePath } from './agent.mjs';
import { stagedManifestViolations } from './manifest-policy.mjs';

const { values } = parseArgs({
  options: { 'allow-manifests': { type: 'boolean' }, allow: { type: 'string', multiple: true } },
});
const allowed = new Set(values.allow ?? []);

let input = '';
for await (const chunk of process.stdin) input += chunk;

const refused = [];
for (const path of input.split('\0').filter(Boolean)) {
  const rel = normalisePath(path);
  if (!rel) {
    refused.push(path);
  } else if (allowed.has(rel)) {
    continue;
  } else if (values['allow-manifests'] && rel.split('/').at(-1) === 'package.json') {
    refused.push(...stagedManifestViolations(rel));
  } else if (isProtectedPath(rel)) {
    refused.push(rel);
  }
}
if (refused.length) {
  console.error(`Protected paths changed:\n${refused.join('\n')}`);
  process.exit(1);
}
