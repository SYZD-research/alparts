// Fails unless every package in a pnpm lockfile resolves from the registry by
// its integrity hash alone. A tarball URL, a git repository or a local
// directory would install code that no registry hash vouches for. The publish
// job runs the copy from the base commit on the rebuilt lockfile before it is
// committed.
//
//   node check-lockfile.mjs <pnpm-lock.yaml>

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const REGISTRY_RESOLUTION = /^\s+resolution: \{integrity: [\w+/=-]+\}$/;

export function lockfileViolations(text) {
  const violations = [];
  text.split('\n').forEach((line, index) => {
    if (/^\s*(?:resolution|tarball):/.test(line) && !REGISTRY_RESOLUTION.test(line)) {
      violations.push(`line ${index + 1}: ${line.trim()}`);
    }
  });
  return violations;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [file] = process.argv.slice(2);
  if (!file) {
    console.error('usage: check-lockfile.mjs <pnpm-lock.yaml>');
    process.exit(2);
  }
  const violations = lockfileViolations(readFileSync(file, 'utf8'));
  if (violations.length) {
    console.error(`Packages that do not resolve from the registry:\n${violations.join('\n')}`);
    process.exit(1);
  }
}
