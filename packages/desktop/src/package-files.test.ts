import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const sourceDirectory = path.dirname(fileURLToPath(import.meta.url));

// The main process is compiled module by module, and the installer contains
// only the files listed in build.files. A module the main process imports but
// the list leaves out makes the packaged app fail before its window opens.
async function mainProcessModules(): Promise<string[]> {
  const seen = new Set<string>();
  const pending = ['main.ts'];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = await readFile(path.join(sourceDirectory, file), 'utf8');
    for (const match of source.matchAll(/(?:from|import\()\s*'\.\/([\w-]+)\.js'/g)) pending.push(`${match[1]}.ts`);
  }
  return [...seen].map((file) => `dist/${file.replace(/\.ts$/, '.js')}`).sort();
}

describe('desktop package contents', () => {
  it('packages every module the main process imports', async () => {
    const manifest = JSON.parse(await readFile(path.join(sourceDirectory, '..', 'package.json'), 'utf8'));
    const packaged = new Set<string>(manifest.build.files);
    const modules = await mainProcessModules();
    assert.ok(modules.includes('dist/strings.js'), 'the import scan found the main process modules');
    assert.deepEqual(modules.filter((module) => !packaged.has(module)), []);
  });
});
