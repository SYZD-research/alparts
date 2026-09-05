import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

test('release preparation requires clean source and emits dependency inventory with artifact hashes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'alparts-release-fixture-'));
  const script = fileURLToPath(new URL('./create-release.mjs', import.meta.url));
  try {
    await mkdir(join(root, 'bin'));
    await mkdir(join(root, 'dist'));
    await writeFile(join(root, '.gitignore'), 'bin/\ndist/\n');
    await writeFile(join(root, 'source.txt'), 'fixture');
    execFileSync('git', ['init', '-q', root]);
    execFileSync('git', ['add', '.'], { cwd: root });
    execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture'], { cwd: root });
    // Deterministic package-manager fixture; the CLI itself and Git clean-tree gate are real.
    await writeFile(join(root, 'bin', 'pnpm'), `#!/usr/bin/env node\nconsole.log(JSON.stringify([{dependencies:{example:{version:'1.2.3',dependencies:{child:{version:'4.5.6'}}}}}]));\n`, { mode: 0o700 });
    await writeFile(join(root, 'dist', 'app.zip'), 'fixture distribution');
    const env = { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}` };
    execFileSync(process.execPath, [script, 'dist', 'stable', '1', 'dist/app.zip'], { cwd: root, env });
    const manifest = JSON.parse(await readFile(join(root, 'dist', 'manifest.json'), 'utf8'));
    const sbom = JSON.parse(await readFile(join(root, 'dist', 'sbom.cdx.json'), 'utf8'));
    assert.equal(manifest.artifacts.length, 2);
    assert.equal(manifest.channel, 'stable');
    assert.deepEqual(sbom.components.map((entry) => entry.name), ['child', 'example']);
    await writeFile(join(root, 'source.txt'), 'dirty');
    const rejected = spawnSync(process.execPath, [script, 'dist', 'stable', '2', 'dist/app.zip'], { cwd: root, env, encoding: 'utf8' });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /clean, committed checkout/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('DR failure writes a private failure record instead of reporting recovery success', async () => {
  const root = await mkdtemp(join(tmpdir(), 'alparts-dr-fixture-'));
  try {
    const backup = join(root, 'fixture.age');
    const report = join(root, 'report.json');
    await writeFile(backup, 'not a backup');
    const script = fileURLToPath(new URL('./dr-drill.mjs', import.meta.url));
    const env = { ...process.env, ALPARTS_RESTORE_ACK: '' };
    const result = spawnSync(process.execPath, [script, backup, report], { env, encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    const recorded = JSON.parse(await readFile(report, 'utf8'));
    assert.equal(recorded.restoreVerified, false);
    assert.equal(recorded.backupSha256.length, 64);
    assert.ok(recorded.elapsedSeconds >= 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});
