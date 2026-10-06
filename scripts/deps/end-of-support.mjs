import { createHash } from 'node:crypto';
import { appendFile, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

// A release line whose newest release is older than this, while a newer line
// exists, is treated as no longer maintained (React 18 stopped at 18.3.1
// without ever being declared end-of-life).
export const STALE_LINE_MONTHS = 12;
// Runtimes are reported this many days before their published end-of-life.
export const RUNTIME_WARNING_DAYS = 90;

const DAY_MS = 24 * 60 * 60 * 1000;
const FETCH_CONCURRENCY = 8;

function unquote(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1).replace(/''/g, "'");
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) return JSON.parse(trimmed);
  return trimmed;
}

function splitPackageId(id) {
  const at = id.lastIndexOf('@');
  if (at <= 0) throw new Error(`Unexpected lockfile package id ${id}`);
  return { name: id.slice(0, at), version: id.slice(at + 1) };
}

// Reads the direct dependencies of every workspace importer and the packages
// the registry has marked deprecated from a pnpm v9 lockfile.
export function parseLockfile(text) {
  const direct = [];
  const deprecated = [];
  let section = null;
  let importer = null;
  let current = null;
  let pkg = null;
  for (const line of text.split(/\r?\n/)) {
    const top = /^(\S[^:]*):\s*$/.exec(line);
    if (top) {
      section = top[1];
      continue;
    }
    if (section === 'importers') {
      let match;
      if ((match = /^ {2}(\S.*):$/.exec(line))) {
        importer = unquote(match[1]);
      } else if (/^ {4}\S/.test(line)) {
        current = null;
      } else if ((match = /^ {6}(\S.*):$/.exec(line))) {
        current = { name: unquote(match[1]), importer };
      } else if (current && (match = /^ {8}version: (.+)$/.exec(line))) {
        const version = unquote(match[1]).replace(/\(.*$/, '');
        if (!/^(link|file|workspace):/.test(version)) direct.push({ ...current, version });
        current = null;
      }
    } else if (section === 'packages') {
      let match;
      if ((match = /^ {2}(\S.*):$/.exec(line))) {
        pkg = splitPackageId(unquote(match[1]));
      } else if (pkg && (match = /^ {4}deprecated: (.+)$/.exec(line))) {
        deprecated.push({ ...pkg, message: unquote(match[1]) });
      }
    }
  }
  return { direct, deprecated };
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  return match ? match.slice(1, 4).map(Number) : null;
}

function isStable(version) {
  return /^\d+\.\d+\.\d+$/.test(version);
}

// The release line semver treats as compatible: the major version, or the
// minor version while the major is still 0.
export function releaseLine(version) {
  const parsed = parseVersion(version);
  if (!parsed) return null;
  return parsed[0] > 0 ? [parsed[0]] : [0, parsed[1]];
}

function compareLines(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function lineLabel(line) {
  return `${line.join('.')}.x`;
}

function day(iso) {
  return iso.slice(0, 10);
}

// Judges one installed npm package against its registry document.
export function assessPackage(doc, version, now, staleMonths = STALE_LINE_MONTHS) {
  const deprecation = doc.versions?.[version]?.deprecated;
  if (deprecation) return { kind: 'deprecated', message: deprecation };

  const line = releaseLine(version);
  const latest = doc['dist-tags']?.latest;
  const latestLine = latest && releaseLine(latest);
  if (!line || !latestLine || compareLines(latestLine, line) <= 0) return null;

  const ltsTagged = Object.entries(doc['dist-tags'] ?? {}).some(([tag, tagged]) =>
    /lts/i.test(tag) && compareLines(releaseLine(tagged) ?? [], line) === 0);
  if (ltsTagged) return null;

  const lastInLine = Object.entries(doc.time ?? {})
    .filter(([candidate]) => isStable(candidate) && compareLines(releaseLine(candidate), line) === 0)
    .map(([candidate, published]) => ({ version: candidate, published }))
    .sort((a, b) => b.published.localeCompare(a.published))[0];
  if (!lastInLine) return null;

  const cutoff = new Date(now);
  cutoff.setUTCMonth(cutoff.getUTCMonth() - staleMonths);
  if (new Date(lastInLine.published) > cutoff) return null;
  return {
    kind: 'stale-line',
    line: lineLabel(line),
    lastVersion: lastInLine.version,
    lastPublished: day(lastInLine.published),
    latest,
  };
}

// Finds the runtimes the repository builds or deploys on.
export function runtimeVersions({ dockerfile, compose, workflows, direct }) {
  const found = new Map();
  const add = (product, name, cycle, source) => {
    const key = `${product}@${cycle}`;
    const entry = found.get(key) ?? { product, name, cycle, sources: new Set() };
    entry.sources.add(source);
    found.set(key, entry);
  };
  for (const match of dockerfile.matchAll(/^FROM\s+node:(\d+)/gm)) add('nodejs', 'Node.js', match[1], 'Dockerfile');
  for (const match of dockerfile.matchAll(/alpine(3\.\d+)/g)) add('alpine-linux', 'Alpine Linux', match[1], 'Dockerfile');
  for (const match of compose.matchAll(/image:\s*postgres:(\d+)/g)) add('postgresql', 'PostgreSQL', match[1], 'docker-compose.yml');
  for (const match of compose.matchAll(/alpine(3\.\d+)/g)) add('alpine-linux', 'Alpine Linux', match[1], 'docker-compose.yml');
  for (const [file, text] of workflows) {
    for (const match of text.matchAll(/node-version:\s*["']?(\d+)/g)) add('nodejs', 'Node.js', match[1], file);
  }
  for (const dep of direct.filter((entry) => entry.name === 'electron')) {
    add('electron', 'Electron', String(parseVersion(dep.version)[0]), dep.importer);
  }
  return [...found.values()].map((entry) => ({ ...entry, sources: [...entry.sources].sort() }));
}

// Judges one runtime release from endoflife.date.
export function assessRuntime(release, now, warningDays = RUNTIME_WARNING_DAYS) {
  if (!release.eolFrom && !release.isEol) return null;
  if (release.isEol) return { kind: 'runtime-ended', eolFrom: release.eolFrom };
  const remaining = Math.ceil((Date.parse(release.eolFrom) - now.getTime()) / DAY_MS);
  if (remaining > warningDays) return null;
  return { kind: 'runtime-ending', eolFrom: release.eolFrom, remaining };
}

function cell(text) {
  return String(text).replace(/[\\|]/g, '\\$&').replace(/\r?\n/g, ' ');
}

function describe(finding) {
  switch (finding.kind) {
    case 'deprecated':
      return `非推奨: ${finding.message}`;
    case 'stale-line':
      return `${finding.line} の最終リリースは ${finding.lastPublished}（${finding.lastVersion}）。最新は ${finding.latest}`;
    case 'runtime-ended':
      return `${finding.eolFrom} にサポート終了`;
    case 'runtime-ending':
      return `${finding.eolFrom} にサポート終了予定（残り ${finding.remaining} 日）`;
    default:
      throw new Error(`Unknown finding kind ${finding.kind}`);
  }
}

export function fingerprint(report) {
  const keys = [
    ...report.runtimes.map((entry) => `runtime:${entry.product}@${entry.cycle}:${entry.finding.kind}`),
    ...report.packages.map((entry) => `npm:${entry.name}@${entry.version}:${entry.finding.kind}`),
    ...report.indirect.map((entry) => `indirect:${entry.name}@${entry.version}`),
  ].sort();
  return createHash('sha256').update(keys.join('\n')).digest('hex').slice(0, 16);
}

export function countFindings(report) {
  return report.runtimes.length + report.packages.length + report.indirect.length;
}

export function renderReport(report, checkedAt) {
  const lines = [
    `<!-- end-of-support:${fingerprint(report)} -->`,
    'サポートが終了した、または保守が止まっている可能性がある依存関係です。',
    '',
  ];
  if (report.runtimes.length) {
    lines.push('### ランタイム', '', '| 対象 | 使用中 | 状態 | 参照元 |', '| --- | --- | --- | --- |');
    for (const entry of report.runtimes) {
      lines.push(`| ${entry.name} | ${cell(entry.cycle)} | ${cell(describe(entry.finding))} | ${cell(entry.sources.join(', '))} |`);
    }
    lines.push('');
  }
  if (report.packages.length) {
    lines.push('### npm パッケージ（直接依存）', '', '| パッケージ | 使用中 | 状態 | 使用箇所 |', '| --- | --- | --- | --- |');
    for (const entry of report.packages) {
      lines.push(`| ${cell(entry.name)} | ${cell(entry.version)} | ${cell(describe(entry.finding))} | ${cell(entry.importers.join(', '))} |`);
    }
    lines.push('');
  }
  if (report.indirect.length) {
    lines.push('### npm パッケージ（間接依存）', '', '| パッケージ | 状態 |', '| --- | --- |');
    for (const entry of report.indirect) {
      lines.push(`| ${cell(`${entry.name}@${entry.version}`)} | ${cell(`非推奨: ${entry.message}`)} |`);
    }
    lines.push('');
  }
  if (!countFindings(report)) lines.push('該当する依存関係はありません。', '');
  lines.push(
    `判定基準: ランタイムは endoflife.date の終了日（${RUNTIME_WARNING_DAYS} 日前から通知）、`
      + `npm パッケージは非推奨の指定、または新しいメジャー版がある中で使用中の系統が ${STALE_LINE_MONTHS} か月以上更新されていないこと。`,
    `確認日時: ${checkedAt.toISOString()}`,
  );
  return `${lines.join('\n')}\n`;
}

async function fetchJson(url, { allowMissing = false } = {}) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const response = await fetch(url, { headers: { accept: 'application/json' } });
      if (allowMissing && response.status === 404) return null;
      if (!response.ok) throw new Error(`${url} responded ${response.status}`);
      return await response.json();
    } catch (error) {
      if (attempt >= 3) throw error;
      await new Promise((done) => setTimeout(done, attempt * 2000));
    }
  }
}

async function mapLimited(items, limit, task) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await task(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

export async function collectReport(root, now) {
  const lockfile = parseLockfile(await readFile(join(root, 'pnpm-lock.yaml'), 'utf8'));
  const workflowDir = join(root, '.github/workflows');
  const workflows = await Promise.all((await readdir(workflowDir))
    .filter((name) => /\.ya?ml$/.test(name))
    .sort()
    .map(async (name) => [`.github/workflows/${name}`, await readFile(join(workflowDir, name), 'utf8')]));

  const runtimes = [];
  const runtimeInputs = runtimeVersions({
    dockerfile: await readFile(join(root, 'Dockerfile'), 'utf8'),
    compose: await readFile(join(root, 'docker-compose.yml'), 'utf8'),
    workflows,
    direct: lockfile.direct,
  });
  for (const runtime of runtimeInputs) {
    const body = await fetchJson(
      `https://endoflife.date/api/v1/products/${runtime.product}/releases/${encodeURIComponent(runtime.cycle)}`,
      { allowMissing: true });
    const finding = body
      ? assessRuntime(body.result, now)
      : { kind: 'runtime-ended', eolFrom: '不明（サポート対象の一覧にありません）' };
    if (finding) runtimes.push({ ...runtime, finding });
  }

  const installed = new Map();
  for (const dep of lockfile.direct) {
    const key = `${dep.name}@${dep.version}`;
    const entry = installed.get(key) ?? { name: dep.name, version: dep.version, importers: new Set() };
    entry.importers.add(dep.importer === '.' ? '(root)' : dep.importer);
    installed.set(key, entry);
  }
  const names = [...new Set([...installed.values()].map((entry) => entry.name))].sort();
  const docs = new Map(await mapLimited(names, FETCH_CONCURRENCY, async (name) =>
    [name, await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`)]));
  const packages = [];
  for (const entry of [...installed.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    const finding = assessPackage(docs.get(entry.name), entry.version, now);
    if (finding) packages.push({ ...entry, importers: [...entry.importers].sort(), finding });
  }

  const directKeys = new Set(installed.keys());
  const indirect = lockfile.deprecated
    .filter((entry) => !directKeys.has(`${entry.name}@${entry.version}`))
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { runtimes, packages, indirect };
}

async function main() {
  const outputIndex = process.argv.indexOf('--output');
  const output = outputIndex > 0 ? process.argv[outputIndex + 1] : null;
  const now = new Date();
  const report = await collectReport(repoRoot, now);
  const markdown = renderReport(report, now);
  if (output) await writeFile(output, markdown);
  else process.stdout.write(markdown);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT,
      `findings=${countFindings(report)}\nfingerprint=${fingerprint(report)}\n`);
  }
  console.error(`${countFindings(report)} end-of-support finding(s)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
