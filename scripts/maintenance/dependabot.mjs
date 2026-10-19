// Helpers for folding Dependabot pull requests into one maintenance PR. The
// workflow fetches each pull request head to refs/maintenance/pr/<number>.
//
//   node dependabot.mjs validate <number>
//     fails unless the pull request only moves existing dependencies
//   node dependabot.mjs incorporated <number>...
//     prints the pull requests whose every change is staged in the index

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { manifestChanges } from './manifest-policy.mjs';

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function readJson(spec) {
  try {
    return JSON.parse(git(['show', spec]));
  } catch {
    return null;
  }
}

// Lists the dependency changes a pull request makes since it branched off,
// and anything about it that cannot be folded in. The lockfile is rebuilt
// from the manifests, so a pull request that only changes the lockfile is
// left for a person.
export function pullRequestChanges(number, show = readJson) {
  const head = `refs/maintenance/pr/${number}`;
  const base = git(['merge-base', 'HEAD', head]).trim();
  const files = git(['diff', '--name-only', '--no-renames', base, head]).split('\n').filter(Boolean);
  const changes = [];
  const problems = [];
  for (const path of files) {
    if (path === 'pnpm-lock.yaml') continue;
    if (path.split('/').at(-1) !== 'package.json') {
      problems.push(`changes ${path}`);
      continue;
    }
    const before = show(`${base}:${path}`);
    const after = show(`${head}:${path}`);
    if (!before || !after) {
      problems.push(`adds or removes ${path}`);
      continue;
    }
    const result = manifestChanges(before, after);
    problems.push(...result.violations.map((violation) => `${path}: ${violation}`));
    changes.push(...result.changes.map((change) => ({ path, ...change })));
  }
  if (changes.length === 0) problems.push('changes no dependency versions');
  return { changes, problems };
}

// True when every change of a pull request is present in the final manifests.
export function isIncorporated(changes, readFinal) {
  return changes.length > 0 && changes.every(({ path, section, name, to }) => {
    const value = readFinal(path)?.[section]?.[name];
    return to === null ? value === undefined : value === to;
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command, ...numbers] = process.argv.slice(2);
  if (command === 'validate' && numbers.length === 1) {
    const { problems } = pullRequestChanges(numbers[0]);
    if (problems.length) {
      console.error(problems.join('; '));
      process.exit(1);
    }
  } else if (command === 'incorporated') {
    const readFinal = (path) => readJson(`:${path}`);
    console.log(numbers.filter((number) => isIncorporated(pullRequestChanges(number).changes, readFinal)).join(' '));
  } else {
    console.error('usage: dependabot.mjs validate <number> | incorporated <number>...');
    process.exit(2);
  }
}
