import assert from 'node:assert/strict';
import { it } from 'node:test';
import { displayText } from './display-text.js';
import { createReadinessCheck } from './readiness-cache.js';

it('rejects misleading controls without excluding ordinary multilingual names', () => {
  for (const character of ['\0', '\n', '\u0085', '\u202e', '\u2066', '\u200b', '\ufeff']) {
    assert.equal(displayText().safeParse(`Alice${character}`).success, false);
  }
  for (const name of ['ゆらぎ', 'مرحبا', 'Zoë', ' Alice ', '한글', 'ⓐ', '😀', '-']) assert.equal(displayText().safeParse(name).success, true);
});
it('rejects names that render as blank', () => {
  for (const name of ['\u2800', 'Al\u2800ice', '\u115f', '\u1160', '\u3164', '\u3000', '\u0301', ' \u0301\u0302 ', '\u2003\u2003']) {
    assert.equal(displayText().safeParse(name).success, false, JSON.stringify(name));
  }
  assert.equal(displayText(100, true).safeParse('').success, true);
  assert.equal(displayText(100, true).safeParse('\u0301').success, false);
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
