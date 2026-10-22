// Gathers the work for a maintenance run from GitHub. Prints one JSON object:
// "outputs" for $GITHUB_OUTPUT and, when there is work, "task", the text the
// agent receives. The workflow writes the files.
//
//   node collect.mjs deps
//   node collect.mjs issue --number <n> [--snapshot <file>]
//
// --snapshot is a JSON file with the issue's title and body when it was
// labelled; the issue is skipped if they have changed since.
//
// Uses GITHUB_REPOSITORY, GITHUB_API_URL and, when set, GH_TOKEN.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

export const FIX_LABEL = 'ai-fix';
export const EOL_LABEL = 'end-of-support';
export const DEPS_BRANCH_PREFIX = 'ai-maintenance/deps-';
export const issueBranchPrefix = (number) => `ai-maintenance/issue-${number}-`;
// Comments from anyone else on a labelled issue are left out of the task.
const TRUSTED_AUTHORS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);

// Text from GitHub reaches the model, so what GitHub does not show is
// removed first: HTML comments, and invisible or direction-changing
// characters. Long text is cut.
export function cleanText(text, limit = 20_000) {
  const cleaned = (text ?? '')
    .replace(/<!--[\s\S]*?(?:-->|$)/g, '')
    .replace(/\p{Cf}/gu, '')
    .replace(/\r\n?/g, '\n')
    .trim();
  return cleaned.length > limit ? `${cleaned.slice(0, limit)}\n[cut]` : cleaned;
}

// Fences text so that nothing in it can close the block.
export function fenced(text) {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((match) => match[0].length));
  const fence = '`'.repeat(longest + 1);
  return `${fence}text\n${text}\n${fence}`;
}

async function api(path) {
  const headers = {
    accept: 'application/vnd.github+json',
    'user-agent': 'alparts-maintenance',
    'x-github-api-version': '2022-11-28',
  };
  if (process.env.GH_TOKEN) headers.authorization = `Bearer ${process.env.GH_TOKEN}`;
  const base = process.env.GITHUB_API_URL ?? 'https://api.github.com';
  const response = await fetch(`${base}/repos/${process.env.GITHUB_REPOSITORY}${path}`, { headers });
  if (!response.ok) throw new Error(`GitHub API ${path} failed (${response.status})`);
  return response.json();
}

export function hasOpenBranch(pulls, prefix) {
  return pulls.some((pull) => pull.head.ref.startsWith(prefix));
}

// npm updates only: the workflow token cannot change workflow files, and
// Docker and Gradle updates stay as Dependabot opened them.
export function dependabotPulls(pulls) {
  return pulls
    .filter((pull) => pull.user.login === 'dependabot[bot]' && pull.head.ref.startsWith('dependabot/npm_and_yarn/'))
    .sort((a, b) => a.number - b.number);
}

export function renderDepsTask(pulls, eol) {
  const lines = ['# Dependency maintenance', ''];
  if (pulls.length) {
    lines.push('## Open Dependabot pull requests', '');
    for (const pull of pulls) {
      const failed = pull.failed.length ? ` (failed in CI: ${pull.failed.join('; ')})` : '';
      lines.push(`- #${pull.number} ${cleanText(pull.title, 300).replace(/\s+/g, ' ')}${failed}`);
    }
    lines.push('');
  }
  // The list quotes deprecation messages from the registry.
  if (eol) lines.push(`## End-of-support list (issue #${eol.number})`, '', fenced(cleanText(eol.body)), '');
  return `${lines.join('\n')}\n`;
}

export function pickIssue(issues, pulls) {
  return issues
    .filter((issue) => !issue.pull_request && issue.state === 'open')
    .filter((issue) => issue.labels.some((label) => label.name === FIX_LABEL))
    .sort((a, b) => a.number - b.number)
    .find((issue) => !hasOpenBranch(pulls, issueBranchPrefix(issue.number)));
}

export function renderIssueTask(issue, comments) {
  const lines = [
    `# GitHub issue #${issue.number}`, '',
    `Opened by ${issue.user.login}.`, '',
    '## Title', '', fenced(cleanText(issue.title, 300)), '',
    '## Description', '', fenced(cleanText(issue.body)), '',
  ];
  const trusted = comments.filter((comment) => TRUSTED_AUTHORS.has(comment.author_association));
  if (trusted.length) {
    lines.push('## Comments from maintainers', '');
    for (const comment of trusted) {
      lines.push(`### ${comment.user.login}, ${comment.created_at.slice(0, 10)}`, '', fenced(cleanText(comment.body, 5_000)), '');
    }
  }
  return `${lines.join('\n')}\n`;
}

// True when the issue's title or body differs from the snapshot taken when
// it was labelled, so the maintainer has not seen the text the model would get.
export function changedSince(issue, snapshot) {
  return issue.title !== snapshot.title || (issue.body ?? '') !== (snapshot.body ?? '');
}

async function failedChecks(sha) {
  const { check_runs: runs } = await api(`/commits/${sha}/check-runs?per_page=100`);
  const failed = [];
  for (const run of runs.filter((run) => run.conclusion === 'failure')) {
    const job = await api(`/actions/jobs/${run.id}`).catch(() => null);
    const steps = job?.steps?.filter((step) => step.conclusion === 'failure').map((step) => step.name) ?? [];
    failed.push(steps.length ? `${run.name} at "${steps.join('", "')}"` : run.name);
  }
  return failed;
}

async function collectDeps() {
  const pulls = await api('/pulls?state=open&per_page=100');
  if (hasOpenBranch(pulls, DEPS_BRANCH_PREFIX)) return { outputs: { busy: 'true', work: 'false' } };
  const updates = [];
  for (const pull of dependabotPulls(pulls)) {
    updates.push({ number: pull.number, title: pull.title, failed: await failedChecks(pull.head.sha) });
  }
  const issues = await api(`/issues?state=open&labels=${EOL_LABEL}&per_page=100`);
  const eol = issues.find((issue) => !issue.pull_request && issue.user.login === 'github-actions[bot]');
  if (!updates.length && !eol) return { outputs: { busy: 'false', work: 'false' } };
  return {
    outputs: { busy: 'false', work: 'true', prs: updates.map((update) => update.number).join(' '), eol: eol?.number ?? '' },
    task: renderDepsTask(updates, eol && { number: eol.number, body: eol.body ?? '' }),
  };
}

async function collectIssue(number, snapshot) {
  const pulls = await api('/pulls?state=open&per_page=100');
  const issue = pickIssue([await api(`/issues/${number}`)], pulls);
  if (!issue) return { outputs: { work: 'false' } };
  if (snapshot && changedSince(issue, snapshot)) {
    return {
      outputs: { work: 'false' },
      notice: `Issue #${issue.number} changed after it was labelled. Add the ${FIX_LABEL} label again to use the new text.`,
    };
  }
  const comments = await api(`/issues/${issue.number}/comments?per_page=100`);
  return { outputs: { work: 'true', number: issue.number }, task: renderIssueTask(issue, comments) };
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { number: { type: 'string' }, snapshot: { type: 'string' } },
  });
  if (!process.env.GITHUB_REPOSITORY) throw new Error('GITHUB_REPOSITORY is required');
  let result;
  if (positionals[0] === 'deps') {
    result = await collectDeps();
  } else if (positionals[0] === 'issue' && /^[1-9][0-9]*$/.test(values.number ?? '')) {
    const snapshot = values.snapshot ? JSON.parse(await readFile(values.snapshot, 'utf8')) : null;
    result = await collectIssue(values.number, snapshot);
  } else {
    throw new Error('usage: collect.mjs deps | issue --number <n> [--snapshot <file>]');
  }
  console.log(JSON.stringify(result));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
