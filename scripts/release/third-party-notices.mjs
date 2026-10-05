import { execFileSync } from 'node:child_process';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const NOTICES_PATH = join(repoRoot, 'packages/client/public/THIRD_PARTY_NOTICES.txt');
const ANDROID_INVENTORY_PATH = join(repoRoot, 'packages/android/runtime-components.json');
const LICENSE_TEXTS_DIR = join(repoRoot, 'scripts/release/license-texts');

const RULE = '-'.repeat(80);
const SECTION = '='.repeat(80);

export function normalizeText(text) {
  return text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').replace(/\s+$/, '');
}

export function licenseExpression(pkg) {
  const legacy = Array.isArray(pkg.licenses)
    ? pkg.licenses.map((entry) => entry && (entry.type || entry.name)).filter(Boolean).join(' OR ')
    : '';
  const declared = typeof pkg.license === 'string' ? pkg.license : pkg.license && pkg.license.type;
  const expression = declared || legacy || '';
  if (!expression.trim()) throw new Error(`${pkg.name || 'unknown'} declares no license`);
  return expression.trim();
}

const LICENSE_FILE = /^(authors?|copyright|copying\d*|licen[cs]es?|licence|notice|unlicen[cs]e|0?bsd|mit|apache)([._-].*)?$/i;
const SOURCE_FILE = /\.(d\.ts|c|cc|cpp|css|h|js|json|mjs|map|ts)$/i;
export function isLicenseFile(name) {
  return LICENSE_FILE.test(name) && !SOURCE_FILE.test(name);
}

// Resolved Maven coordinates carry no license metadata, so the curated map
// below is the reviewed license for each groupId shipped in the Android app.
// An unknown groupId fails the build instead of silently mislabeling it.
const MAVEN_GROUP_LICENSES = [
  [/^androidx\./, 'Apache-2.0'],
  [/^org\.jetbrains(\.|$)/, 'Apache-2.0'],
];
export function mavenLicense(groupId) {
  const match = MAVEN_GROUP_LICENSES.find(([pattern]) => pattern.test(groupId));
  if (!match) throw new Error(`Maven groupId ${groupId} has no curated license entry`);
  return match[1];
}

export function npmPurl(name, version) {
  const short = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${short}@${encodeURIComponent(version)}`;
}

function pnpmList(root) {
  return JSON.parse(execFileSync('pnpm', ['-r', 'list', '--prod', '--depth', 'Infinity', '--json'],
    { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
}

function collectNpmIds(root) {
  const ids = new Map();
  const visit = (entries, depth = 0) => {
    if (depth > 256) throw new Error('Dependency graph exceeds depth limit');
    for (const [alias, dependency] of Object.entries(entries || {})) {
      const name = dependency.name || alias;
      const version = dependency.version;
      if (typeof version === 'string' && !version.startsWith('link:')) ids.set(`${name}@${version}`, { name, version });
      visit(dependency.dependencies, depth + 1);
      visit(dependency.optionalDependencies, depth + 1);
    }
  };
  for (const project of pnpmList(root)) { visit(project.dependencies); visit(project.optionalDependencies); }
  return [...ids.values()];
}

async function findStoreDir(root, storeEntries, name, version) {
  const prefix = `${name.replaceAll('/', '+')}@${version}`;
  const match = storeEntries
    .filter((entry) => entry === prefix || entry.startsWith(`${prefix}_`) || entry.startsWith(`${prefix}(`))
    .sort()[0];
  if (!match) throw new Error(`Package ${name}@${version} is listed but missing from node_modules/.pnpm`);
  return join(root, 'node_modules', '.pnpm', match, 'node_modules', name);
}

async function readPackageLicense(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    throw new Error(`Cannot read package directory ${dir}`);
  }
  const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8'));
  const files = entries
    .filter((entry) => entry.isFile() && isLicenseFile(entry.name))
    .map((entry) => entry.name)
    .sort((a, b) => a.localeCompare(b));
  const parts = [];
  for (const file of files) parts.push(normalizeText(await readFile(join(dir, file), 'utf8')));
  return { license: licenseExpression(pkg), text: parts.join('\n\n') };
}

export async function collectNpmNotices(root) {
  let storeEntries;
  try {
    storeEntries = await readdir(join(root, 'node_modules', '.pnpm'));
  } catch {
    throw new Error('node_modules/.pnpm not found; run pnpm install first');
  }
  const notices = [];
  for (const { name, version } of collectNpmIds(root)) {
    const dir = await findStoreDir(root, storeEntries, name, version);
    const { license, text } = await readPackageLicense(dir);
    notices.push({ name, version, purl: npmPurl(name, version), license, text });
  }
  return notices.sort((a, b) => a.purl.localeCompare(b.purl));
}

export async function collectElectronNotice(root) {
  const dir = join(root, 'packages', 'desktop', 'node_modules', 'electron');
  const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8'));
  let text = '';
  try {
    text = normalizeText(await readFile(join(dir, 'LICENSE'), 'utf8'));
  } catch { /* license field still records MIT */ }
  return { name: 'Electron', version: pkg.version, purl: npmPurl('electron', pkg.version), license: 'MIT', text };
}

export async function collectAndroidNotices(root, inventoryPath = ANDROID_INVENTORY_PATH) {
  let components;
  try {
    components = JSON.parse(await readFile(inventoryPath, 'utf8'));
  } catch {
    throw new Error('packages/android/runtime-components.json is missing; run packages/android/gradlew -p packages/android runtimeInventory');
  }
  const groups = new Map();
  for (const component of components) {
    const license = mavenLicense(component.group);
    const id = `${component.group}:${component.name}@${component.version}`;
    if (!groups.has(license)) groups.set(license, []);
    groups.get(license).push(id);
  }
  const sections = [];
  for (const [license, ids] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const text = normalizeText(await readFile(join(LICENSE_TEXTS_DIR, `${license}.txt`), 'utf8'));
    sections.push({ license, components: ids.sort(), text });
  }
  return sections;
}

export function renderNotices({ npm, electron, android }) {
  const out = [
    SECTION,
    'alparts — third-party license notices',
    SECTION,
    '',
    'This product bundles third-party software components. Each component is',
    'listed with the license declared by its authors; where the upstream package',
    'ships a license file, its text follows the entry.',
    '',
    'Generated by scripts/release/third-party-notices.mjs — do not edit.',
    'Regenerate after dependency changes with: pnpm notices',
    '',
    SECTION,
    'npm packages (server image, web client, desktop application)',
    SECTION,
    '',
  ];
  for (const notice of npm) {
    out.push(
      `${notice.name} ${notice.version}`,
      `License: ${notice.license}`,
      `Package: ${notice.purl}`,
      '',
      notice.text || 'The published package does not include a license file.',
      RULE,
      '',
    );
  }
  out.push(
    SECTION,
    'Desktop runtime',
    SECTION,
    '',
    `${electron.name} ${electron.version}`,
    `License: ${electron.license}`,
    `Package: ${electron.purl}`,
    '',
    electron.text,
    '',
    'Electron also bundles Chromium, Node.js, and other components. Their',
    'license texts ship inside every desktop package next to the executable as',
    'LICENSE.electron.txt and LICENSES.chromium.html.',
    RULE,
    '',
    SECTION,
    'Android runtime libraries',
    SECTION,
    '',
    'The Android package embeds these Maven components resolved by the Gradle',
    'build (see packages/android/runtime-components.json).',
    '',
  );
  for (const section of android) {
    out.push(
      ...section.components.map((id) => `${id} — ${section.license}`),
      '',
      `License: ${section.license}`,
      '',
      section.text,
      RULE,
      '',
    );
  }
  return `${out.join('\n').trimEnd()}\n`;
}

export async function buildNotices(root = repoRoot) {
  const [npm, electron, android] = await Promise.all([
    collectNpmNotices(root), collectElectronNotice(root), collectAndroidNotices(root),
  ]);
  const missing = npm.filter((notice) => !notice.text).map((notice) => `${notice.name}@${notice.version}`);
  if (missing.length) {
    process.stderr.write(`warning: no license file shipped: ${missing.join(', ')}\n`);
  }
  return renderNotices({ npm, electron, android });
}

async function main() {
  const check = process.argv.includes('--check');
  const content = await buildNotices();
  if (check) {
    let current = '';
    try {
      current = await readFile(NOTICES_PATH, 'utf8');
    } catch { /* missing counts as stale */ }
    if (current === content) {
      process.stdout.write('THIRD_PARTY_NOTICES.txt is up to date\n');
      return;
    }
    process.stderr.write('THIRD_PARTY_NOTICES.txt is stale; regenerate with: pnpm notices\n');
    process.exit(1);
  }
  await writeFile(NOTICES_PATH, content);
  process.stdout.write(`Wrote ${NOTICES_PATH}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exit(1); });
}
