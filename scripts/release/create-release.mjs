import { execFileSync } from 'node:child_process';
import { readFile, writeFile, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { dependencyName } from './third-party-notices.mjs';
import { artifactDigest, validateManifest } from './update-manifest.mjs';

// This creates reviewable unsigned metadata. The offline signer owns the next step.
const [directory, channel, sequence, ...artifacts] = process.argv.slice(2);
if (!directory || !channel || !sequence || artifacts.length === 0) {
  throw new Error('Usage: create-release.mjs output-dir channel sequence artifact ...');
}
if (!(await lstat(directory)).isDirectory()) throw new Error('Output directory must exist');
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], { encoding: 'utf8' }).trim();
if (dirty) throw new Error('Release metadata requires a clean, committed checkout');
const dependencies = JSON.parse(execFileSync('pnpm', ['-r', 'list', '--prod', '--depth', 'Infinity', '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
const components = new Map();
function visit(entries, depth = 0) {
  if (depth > 256) throw new Error('Dependency graph exceeds depth limit');
  for (const [alias, dependency] of Object.entries(entries || {})) {
    const name = dependencyName(alias, dependency);
    const version = dependency.version;
    if (typeof version !== 'string') throw new Error('Unresolved dependency');
    if (!version.startsWith('link:')) {
      const purl = `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${encodeURIComponent(version)}`;
      components.set(purl, { type: 'library', 'bom-ref': purl, name, version, purl });
    }
    visit(dependency.dependencies, depth + 1);
    visit(dependency.optionalDependencies, depth + 1);
  }
}
for (const project of dependencies) { visit(project.dependencies); visit(project.optionalDependencies); }
// Android inventory comes from Gradle's actual resolved runtime graph, not a hand-maintained list.
if (artifacts.some((filename) => /\.(apk|aab)$/.test(filename))) {
  const android = JSON.parse(await readFile('packages/android/app/build/reports/runtime-components.json', 'utf8'));
  for (const component of android) components.set(component.purl, component);
}
const now = new Date();
const sbom = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
  metadata: { timestamp: now.toISOString(), component: { type: 'application', name: 'alparts', version: commit } },
  components: [...components.values()].sort((a, b) => a.purl.localeCompare(b.purl)) };
const sbomPath = join(directory, 'sbom.cdx.json');
await writeFile(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`, { flag: 'wx' });
const entries = await Promise.all([...artifacts, sbomPath].map(artifactDigest));
for (const filename of artifacts) {
  if (resolve(filename) !== join(resolve(directory), (await artifactDigest(filename)).name)) {
    throw new Error('Put all release artifacts in the output directory before preparing metadata');
  }
}
const manifest = validateManifest({ version: 1, product: 'alparts', channel, sequence: Number(sequence),
  issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 86400000).toISOString(), commit, artifacts: entries });
await writeFile(join(directory, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
process.stdout.write('Unsigned manifest and SBOM created. Provenance must be attested by the isolated build workflow.\n');
