import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { desktopLocale, desktopStrings, normalizeDesktopLocale } from './strings.js';

describe('desktop language', () => {
  it('follows the first supported system language', () => {
    assert.equal(desktopLocale(['ja-JP', 'en-US']), 'ja');
    assert.equal(desktopLocale(['en-GB', 'ja']), 'en');
    assert.equal(desktopLocale(['fr-FR', 'ja_JP']), 'ja');
    assert.equal(desktopLocale(['de-DE']), 'en');
    assert.equal(desktopLocale([]), 'en');
  });

  it('accepts only supported languages from the renderer', () => {
    assert.equal(normalizeDesktopLocale('ja'), 'ja');
    assert.equal(normalizeDesktopLocale('en'), 'en');
    for (const value of ['fr', 'JA', '', null, 1, { locale: 'ja' }]) {
      assert.throws(() => normalizeDesktopLocale(value), /INVALID_LOCALE/);
    }
  });

  it('has every string in both languages', () => {
    const japanese = desktopStrings('ja');
    const english = desktopStrings('en');
    assert.deepEqual(Object.keys(english).sort(), Object.keys(japanese).sort());
    for (const value of Object.values(english)) assert.doesNotMatch(value, /[぀-ヿ一-鿿]/);
  });
});
