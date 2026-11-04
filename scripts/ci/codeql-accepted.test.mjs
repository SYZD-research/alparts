import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACCEPTED, acceptedEntry, checkoutReader, takeOutAccepted } from './codeql-accepted.mjs';

const REVIEW = 'scripts/maintenance/review.mjs';
const COLLECT = 'scripts/maintenance/collect.mjs';

const location = (uri, line) => ({ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } });

// A path-problem result with one path per source, each ending at the sink.
function result({ rule = 'js/file-access-to-http', file = COLLECT, line = 62, sources = [[REVIEW, 181]] } = {}) {
  return {
    ruleId: rule,
    locations: [location(file, line)],
    codeFlows: [{
      threadFlows: sources.map(([uri, at]) => ({ locations: [{ location: location(uri, at) }, { location: location(file, line) }] })),
    }],
  };
}

// The event file is read on line 181 and the review on line 458; line 300
// reads some other file.
const LINES = {
  [REVIEW]: { 181: ACCEPTED[0].source.code, 458: ACCEPTED[1].source.code, 300: "const notes = await readFile(other, 'utf8');" },
};
const readLine = (file, line) => LINES[file]?.[line];

test('takes out the two accepted paths and nothing else', () => {
  const keep = result({ rule: 'js/request-forgery' });
  const sarif = { runs: [{ results: [result(), result({ line: 59, sources: [[REVIEW, 458]] }), keep] }] };
  const taken = takeOutAccepted(sarif, readLine);
  assert.deepEqual(taken.map(({ entry }) => entry), [ACCEPTED[0], ACCEPTED[1]]);
  assert.deepEqual(sarif.runs[0].results, [keep]);
});

test('matches the source by its code, not its line number', () => {
  const moved = (file, line) => (file === REVIEW && line === 190 ? ACCEPTED[0].source.code : undefined);
  assert.equal(acceptedEntry(result({ sources: [[REVIEW, 190]] }), moved), ACCEPTED[0]);
  assert.equal(acceptedEntry(result({ sources: [[REVIEW, 181]] }), moved), null);
});

test('keeps a new path to the same place', () => {
  assert.equal(acceptedEntry(result({ sources: [[REVIEW, 300]] }), readLine), null);
  assert.equal(acceptedEntry(result({ sources: [['scripts/maintenance/agent.mjs', 181]] }), readLine), null);
});

test('keeps a result when any one of its paths is not accepted', () => {
  assert.equal(acceptedEntry(result({ sources: [[REVIEW, 181], [REVIEW, 300]] }), readLine), null);
});

test('keeps the rule elsewhere and other rules in the same file', () => {
  assert.equal(acceptedEntry(result({ file: 'packages/desktop/src/main.ts' }), readLine), null);
  assert.equal(acceptedEntry(result({ rule: 'js/request-forgery' }), readLine), null);
});

test('keeps a result without paths', () => {
  const plain = { ruleId: 'js/file-access-to-http', locations: [location(COLLECT, 62)] };
  assert.equal(acceptedEntry(plain, readLine), null);
});

test('leaves runs without results as they are', () => {
  const sarif = { runs: [{ tool: { driver: { name: 'CodeQL' } } }] };
  assert.deepEqual(takeOutAccepted(sarif, readLine), []);
  assert.deepEqual(sarif, { runs: [{ tool: { driver: { name: 'CodeQL' } } }] });
});

test('every accepted source is still in the checkout, once', () => {
  const read = checkoutReader();
  for (const { source } of ACCEPTED) {
    const matches = [];
    for (let line = 1; read(source.file, line) !== undefined; line += 1) {
      if (read(source.file, line) === source.code) matches.push(line);
    }
    assert.equal(matches.length, 1, `${source.file}: ${source.code}`);
  }
});
