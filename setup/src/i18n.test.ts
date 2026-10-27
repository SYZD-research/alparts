import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detectLanguage, MESSAGES, translator } from './i18n.ts';

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

test('both languages carry the same messages with the same placeholders', () => {
  assert.deepEqual(Object.keys(MESSAGES.en).sort(), Object.keys(MESSAGES.ja).sort());
  for (const [key, japanese] of Object.entries(MESSAGES.ja)) {
    const english = MESSAGES.en[key as keyof typeof MESSAGES.en];
    assert.ok(japanese.trim() && english.trim(), key);
    assert.deepEqual(placeholders(english), placeholders(japanese), key);
  }
});

test('the language follows the locale, English outside Japanese', () => {
  assert.equal(detectLanguage({ LANG: 'ja_JP.UTF-8' }), 'ja');
  assert.equal(detectLanguage({ LC_ALL: 'ja', LANG: 'en_US.UTF-8' }), 'ja');
  assert.equal(detectLanguage({ LANG: 'en_US.UTF-8' }), 'en');
  assert.equal(detectLanguage({ LANG: 'jam_JM' }), 'en');
  assert.equal(detectLanguage({}), 'en');
});

test('values fill their placeholders and unknown ones stay visible', () => {
  const t = translator('en');
  assert.equal(t('done.url', { url: 'https://chat.example.com' }), 'Alparts is available at https://chat.example.com.');
  assert.equal(t('done.url'), 'Alparts is available at {url}.');
});
