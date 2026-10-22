import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { describe, it } from 'node:test';

// electron-builder writes the AppImage's launcher entry, and unless the configuration says
// otherwise its Exec line carries --no-sandbox. This runs its own code on this package's
// configuration instead of repeating its rules.
const builder = createRequire(createRequire(import.meta.url).resolve('electron-builder'));
const AppImageTarget = builder('app-builder-lib/out/targets/appimage/AppImageTarget.js').default;
const { LinuxTargetHelper } = builder('app-builder-lib/out/targets/LinuxTargetHelper.js');

interface BuildConfig {
  productName: string;
  linux: { executableName: string; executableArgs?: string[] };
}

interface Manifest {
  version: string;
  description: string;
  desktopName: string;
  build: BuildConfig;
}

describe('Linux packaging', () => {
  it('writes the AppImage launcher entry without a sandbox switch', async () => {
    const manifest = await readManifest();
    assert.equal(await appImageExecLine(manifest, manifest.build), 'Exec=AppRun %U');
  });

  it('shows a switch that the configuration asks for', async () => {
    const manifest = await readManifest();
    const build = { ...manifest.build, linux: { ...manifest.build.linux, executableArgs: ['--no-sandbox'] } };
    assert.equal(await appImageExecLine(manifest, build), 'Exec=AppRun --no-sandbox %U');
  });
});

async function readManifest(): Promise<Manifest> {
  return JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as Manifest;
}

async function appImageExecLine(manifest: Manifest, build: BuildConfig): Promise<string> {
  const packager = {
    config: build,
    platformSpecificBuildOptions: build.linux,
    appInfo: {
      productName: build.productName,
      sanitizedProductName: build.productName,
      description: manifest.description,
      buildVersion: manifest.version,
    },
    executableName: build.linux.executableName,
    fileAssociations: [],
    info: { metadata: { desktopName: manifest.desktopName } },
  };
  const target = new AppImageTarget(null, packager, new LinuxTargetHelper(packager), 'release');
  const entry: string = await target.desktopEntry.value;
  const line = entry.split('\n').find((candidate) => candidate.startsWith('Exec='));
  assert.ok(line, 'the launcher entry has an Exec line');
  return line;
}
