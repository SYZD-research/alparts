import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  normalizeText, licenseExpression, isLicenseFile, mavenLicense, npmPurl,
  renderNotices, collectAndroidNotices,
} from './third-party-notices.mjs';

test('normalizeText strips BOM, CRLF and trailing whitespace', () => {
  assert.equal(normalizeText('\uFEFFa\r\nb\r\nc\n\n\n'), 'a\nb\nc');
});

test('licenseExpression accepts SPDX string, legacy object and licenses array', () => {
  assert.equal(licenseExpression({ name: 'a', license: 'MIT' }), 'MIT');
  assert.equal(licenseExpression({ name: 'a', license: { type: 'Apache-2.0' } }), 'Apache-2.0');
  assert.equal(licenseExpression({ name: 'a', licenses: [{ type: 'MIT' }, { type: 'ISC' }] }), 'MIT OR ISC');
  assert.throws(() => licenseExpression({ name: 'unlicensed' }), /no license/);
});

test('isLicenseFile matches notice files and rejects source files', () => {
  for (const name of ['LICENSE', 'LICENSE.md', 'LICENCE', 'LICENSE-MIT', 'COPYING', 'COPYING3',
    'NOTICE', 'NOTICE.txt', 'copyright', 'AUTHORS', 'UNLICENSE', 'LICENSE_APACHE']) {
    assert.ok(isLicenseFile(name), name);
  }
  for (const name of ['license.d.ts', 'LICENSE.js', 'package.json', 'index.ts', 'README.md', 'CHANGES']) {
    assert.ok(!isLicenseFile(name), name);
  }
});

test('mavenLicense returns curated license and rejects unknown groupIds', () => {
  assert.equal(mavenLicense('androidx.webkit'), 'Apache-2.0');
  assert.equal(mavenLicense('org.jetbrains.kotlin'), 'Apache-2.0');
  assert.equal(mavenLicense('org.jetbrains'), 'Apache-2.0');
  assert.throws(() => mavenLicense('com.example'), /no curated license/);
});

test('npmPurl encodes scoped names like the release SBOM', () => {
  assert.equal(npmPurl('express', '5.2.1'), 'pkg:npm/express@5.2.1');
  assert.equal(npmPurl('@noble/hashes', '2.4.0'), 'pkg:npm/%40noble/hashes@2.4.0');
});

test('renderNotices is deterministic and lists every component', () => {
  const data = {
    npm: [
      { name: 'b-pkg', version: '2.0.0', purl: 'pkg:npm/b-pkg@2.0.0', license: 'ISC', text: 'isc text' },
      { name: 'a-pkg', version: '1.0.0', purl: 'pkg:npm/a-pkg@1.0.0', license: 'MIT', text: '' },
    ],
    electron: { name: 'Electron', version: '1.0.0', purl: 'pkg:npm/electron@1.0.0', license: 'MIT', text: 'mit text' },
    android: [{ license: 'Apache-2.0', components: ['androidx.x:y@1'], text: 'apache text' }],
  };
  const output = renderNotices(data);
  assert.equal(output, renderNotices(data));
  assert.match(output, /a-pkg 1\.0\.0\nLicense: MIT\nPackage: pkg:npm\/a-pkg@1\.0\.0\n\nThe published package does not include a license file\./);
  assert.match(output, /b-pkg 2\.0\.0\nLicense: ISC\nPackage: pkg:npm\/b-pkg@2\.0\.0\n\nisc text/);
  assert.match(output, /Electron 1\.0\.0[\s\S]*LICENSES\.chromium\.html/);
  assert.match(output, /androidx\.x:y@1 — Apache-2\.0[\s\S]*apache text/);
  assert.ok(output.endsWith('\n') && !output.endsWith('\n\n'));
});

test('collectAndroidNotices groups components by license', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'notices-'));
  try {
    const inventory = join(dir, 'runtime-components.json');
    await writeFile(inventory, JSON.stringify([
      { group: 'androidx.webkit', name: 'webkit', version: '1.0.0' },
      { group: 'org.jetbrains.kotlin', name: 'kotlin-stdlib', version: '1.7.10' },
    ]));
    const sections = await collectAndroidNotices('.', inventory);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].license, 'Apache-2.0');
    assert.deepEqual(sections[0].components,
      ['androidx.webkit:webkit@1.0.0', 'org.jetbrains.kotlin:kotlin-stdlib@1.7.10']);
    assert.match(sections[0].text, /Apache License/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('collectAndroidNotices fails on unknown groupId and missing inventory', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'notices-'));
  try {
    const inventory = join(dir, 'runtime-components.json');
    await writeFile(inventory, JSON.stringify([{ group: 'com.example', name: 'x', version: '1' }]));
    await assert.rejects(collectAndroidNotices('.', inventory), /no curated license/);
    await assert.rejects(collectAndroidNotices('.', join(dir, 'absent.json')), /runtime-components/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
