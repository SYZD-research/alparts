// Takes the CodeQL findings accepted after review out of the SARIF files the
// analyze step wrote, before they are uploaded and counted
// (.github/workflows/codeql.yml):
//
//   node scripts/ci/codeql-accepted.mjs <dir>
//
// A result is taken out only when its rule and file match an entry and every
// path in it starts at that entry's source: the source line, read from the
// checkout, must be exactly the entry's code. Moving the line keeps the
// match; changing it, or a new path from anywhere else to the same place,
// makes the finding count again. Each finding taken out is printed to the
// job log. The risk register records the acceptance (R-065).

import { readFileSync } from 'node:fs';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export const ACCEPTED = [
  {
    rule: 'js/file-access-to-http',
    file: 'scripts/maintenance/collect.mjs',
    source: {
      file: 'scripts/maintenance/review.mjs',
      code: "const { comment, issue } = JSON.parse(await readFile(eventPath, 'utf8'));",
    },
    reason: "review.mjs collect reads the commenter and the pull request from GitHub's event file and asks the repository's own GitHub API about them.",
  },
  {
    rule: 'js/file-access-to-http',
    file: 'scripts/maintenance/collect.mjs',
    source: {
      file: 'scripts/maintenance/review.mjs',
      code: "const result = parseReview(JSON.parse(await readFile(review, 'utf8')));",
    },
    reason: "review.mjs post sends the review the model wrote, read from the review job's artifact, to the pull request.",
  },
];

const uriOf = (location) => location?.physicalLocation?.artifactLocation?.uri;
const lineOf = (location) => location?.physicalLocation?.region?.startLine;

// The first location of every path in the result; empty when it has none.
function pathSources(result) {
  return (result.codeFlows ?? [])
    .flatMap((flow) => flow.threadFlows ?? [])
    .map((thread) => thread.locations?.[0]?.location);
}

// The entry that accepts the result, or null. readLine(file, line) returns
// the trimmed text of a 1-based line of a file in the checkout.
export function acceptedEntry(result, readLine, accepted = ACCEPTED) {
  const sources = pathSources(result);
  if (!sources.length) return null;
  return accepted.find((entry) => result.ruleId === entry.rule
    && uriOf(result.locations?.[0]) === entry.file
    && sources.every((source) => uriOf(source) === entry.source.file
      && readLine(entry.source.file, lineOf(source)) === entry.source.code)) ?? null;
}

// Removes the accepted results from the SARIF in place and returns them with
// the entries that accepted them.
export function takeOutAccepted(sarif, readLine, accepted = ACCEPTED) {
  const taken = [];
  for (const run of sarif.runs ?? []) {
    if (!Array.isArray(run.results)) continue;
    run.results = run.results.filter((result) => {
      const entry = acceptedEntry(result, readLine, accepted);
      if (entry) taken.push({ result, entry });
      return !entry;
    });
  }
  return taken;
}

export function checkoutReader(root = repoRoot) {
  const files = new Map();
  return (file, line) => {
    if (!files.has(file)) {
      let lines = null;
      try {
        lines = readFileSync(join(root, file), 'utf8').split(/\r?\n/);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      files.set(file, lines);
    }
    return files.get(file)?.[line - 1]?.trim();
  };
}

async function main() {
  const dir = process.argv[2];
  if (!dir) throw new Error('usage: codeql-accepted.mjs <dir with SARIF files>');
  const readLine = checkoutReader();
  for (const name of (await readdir(dir)).filter((file) => file.endsWith('.sarif')).sort()) {
    const path = join(dir, name);
    const sarif = JSON.parse(await readFile(path, 'utf8'));
    const taken = takeOutAccepted(sarif, readLine);
    if (!taken.length) continue;
    await writeFile(path, JSON.stringify(sarif));
    for (const { result, entry } of taken) {
      const from = [...new Set(pathSources(result).map((source) => `${uriOf(source)}:${lineOf(source)}`))].join(', ');
      console.log(`Accepted ${result.ruleId} at ${uriOf(result.locations[0])}:${lineOf(result.locations[0])} from ${from}: ${entry.reason}`);
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
