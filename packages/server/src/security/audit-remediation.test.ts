import assert from 'node:assert/strict';
import { it } from 'node:test';
import { displayText } from './display-text.js';
import { createReadinessCheck } from './readiness-cache.js';

it('rejects misleading controls without excluding ordinary multilingual names', () => {
  for (const character of ['\0', '\n', '\u0085', '\u202e', '\u2066', '\u200b', '\ufeff']) {
    assert.equal(displayText().safeParse(`Alice${character}`).success, false);
  }
  for (const name of ['ゆらぎ', 'مرحبا', 'Zoë', ' Alice ']) assert.equal(displayText().safeParse(name).success, true);
});
it('coalesces concurrent readiness probes and also caches failures', async () => {
  let calls = 0;
  let finish!: () => void;
  const check = createReadinessCheck(async () => {
    calls++;
    await new Promise<void>((resolve) => { finish = resolve; });
    throw new Error('storage unavailable');
  });
  const pending = Array.from({ length: 100 }, () => check());
  await Promise.resolve();
  assert.equal(calls, 1);
  finish();
  assert.deepEqual(await Promise.all(pending), Array(100).fill(false));
  assert.equal(await check(), false);
  assert.equal(calls, 1);
});
