// Gathers the work for a maintenance run from GitHub and writes the task the
// agent receives. Prints key=value lines for $GITHUB_OUTPUT.
//
//   node collect.mjs deps --task <file>
//   node collect.mjs issue [--number <n>] --task <file>
//
// Uses GITHUB_REPOSITORY, GITHUB_API_URL and, when set, GH_TOKEN.

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

export const FIX_LABEL = 'ai-fix';
export const EOL_LABEL = 'end-of-support';
export const DEPS_BRANCH_PREFIX = 'ai-maintenance/deps-';
export const issueBranchPrefix = (number) => `ai-maintenance/issue-${number}-`;
// Comments from anyone else on a labelled issue are left out of the task.
const TRUSTED_AUTHORS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);

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
      lines.push(`- #${pull.number} ${pull.title}${failed}`);
    }
    lines.push('');
  }
  if (eol) lines.push(`## End-of-support list (issue #${eol.number})`, '', eol.body.trim(), '');
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
  const lines = [`# GitHub issue #${issue.number}: ${issue.title}`, '', `Opened by ${issue.user.login}.`, '', (issue.body ?? '').trim(), ''];
  const trusted = comments.filter((comment) => TRUSTED_AUTHORS.has(comment.author_association));
  if (trusted.length) {
    lines.push('## Comments from maintainers', '');
    for (const comment of trusted) lines.push(`### ${comment.user.login}, ${comment.created_at.slice(0, 10)}`, '', comment.body.trim(), '');
  }
  return `${lines.join('\n')}\n`;
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

async function collectDeps(task) {
  const pulls = await api('/pulls?state=open&per_page=100');
  if (hasOpenBranch(pulls, DEPS_BRANCH_PREFIX)) return { busy: 'true', work: 'false' };
  const updates = [];
  for (const pull of dependabotPulls(pulls)) {
    updates.push({ number: pull.number, title: pull.title, failed: await failedChecks(pull.head.sha) });
  }
  const issues = await api(`/issues?state=open&labels=${EOL_LABEL}&per_page=100`);
  const eol = issues.find((issue) => !issue.pull_request && issue.user.login === 'github-actions[bot]');
  if (!updates.length && !eol) return { busy: 'false', work: 'false' };
  await writeFile(task, renderDepsTask(updates, eol && { number: eol.number, body: eol.body ?? '' }));
  return { busy: 'false', work: 'true', prs: updates.map((update) => update.number).join(' '), eol: eol?.number ?? '' };
}

async function collectIssue(task, number) {
  const pulls = await api('/pulls?state=open&per_page=100');
  const candidates = number
    ? [await api(`/issues/${number}`)]
    : await api(`/issues?state=open&labels=${FIX_LABEL}&per_page=100`);
  const issue = pickIssue(candidates, pulls);
  if (!issue) return { work: 'false' };
  const comments = await api(`/issues/${issue.number}/comments?per_page=100`);
  await writeFile(task, renderIssueTask(issue, comments));
  return { work: 'true', number: issue.number };
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { task: { type: 'string' }, number: { type: 'string' } },
  });
  if (!values.task || !process.env.GITHUB_REPOSITORY) throw new Error('--task and GITHUB_REPOSITORY are required');
  let outputs;
  if (positionals[0] === 'deps') outputs = await collectDeps(values.task);
  else if (positionals[0] === 'issue') outputs = await collectIssue(values.task, values.number || null);
  else throw new Error('usage: collect.mjs deps|issue --task <file>');
  for (const [key, value] of Object.entries(outputs)) console.log(`${key}=${value}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
