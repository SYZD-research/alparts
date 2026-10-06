/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest';
import { en, type MessageKey } from './en';
import { translate } from './index';
import { detectLocale, formattingLocale } from './locale';

const JAPANESE = /[\u3000-\u303f\u3040-\u30ff\u4e00-\u9fff]/;
const PLACEHOLDER = /\{(\w+)\}/g;

function placeholders(text: string): string[] {
  return [...text.matchAll(PLACEHOLDER)].map((match) => match[1]).sort();
}

describe('language detection', () => {
  it('uses the first supported language in the preference order', () => {
    expect(detectLocale(['ja-JP', 'en-US'])).toBe('ja');
    expect(detectLocale(['en-GB', 'ja'])).toBe('en');
    expect(detectLocale(['fr-FR', 'ja-JP'])).toBe('ja');
    expect(detectLocale(['JA'])).toBe('ja');
  });

  it('falls back to English for unsupported or missing languages', () => {
    expect(detectLocale(['fr-FR', 'de'])).toBe('en');
    expect(detectLocale([])).toBe('en');
  });

  it('keeps the regional variant of the chosen language for formatting', () => {
    expect(formattingLocale('en', ['en-GB', 'ja-JP'])).toBe('en-GB');
    expect(formattingLocale('ja', ['en-GB'])).toBe('ja-JP');
    expect(formattingLocale('en', ['ja-JP'])).toBe('en-US');
  });
});

describe('translate', () => {
  it('shows the Japanese key itself, without any context suffix', () => {
    expect(translate('ja', '未読{count}件', { count: 3 })).toBe('未読3件');
    expect(translate('ja', 'すべて|notification-level')).toBe('すべて');
  });

  it('uses the English catalog, including plural forms', () => {
    expect(translate('en', '閉じる')).toBe('Close');
    expect(translate('en', 'メンション{count}件', { count: 1 })).toBe('1 mention');
    expect(translate('en', 'メンション{count}件', { count: 2 })).toBe('2 mentions');
  });
});

describe('English catalog', () => {
  const sample = (key: string) => Object.fromEntries(placeholders(key).map((name) => [name, 2]));

  it('translates every message completely, keeping its placeholders', () => {
    const problems = (Object.keys(en) as MessageKey[]).filter((key) => {
      const message = en[key];
      const text = translate('en', key, sample(key));
      return JAPANESE.test(text)
        || /\{\w+\}/.test(text)
        || (typeof message === 'string' && placeholders(message).join() !== placeholders(key).join());
    });
    expect(problems).toEqual([]);
  });
});

describe('source text', () => {
  // Markers stored in message content; they are compared, never shown.
  const internalMarkers = ['[表示できないメッセージ]', '[メッセージを検証できませんでした]', '[改ざんを検出しました]'];
  const sources = import.meta.glob<string>(
    ['../**/*.{ts,tsx}', '!../i18n/**', '!../**/*.test.{ts,tsx}', '!../test-setup.ts'],
    { query: '?raw', import: 'default', eager: true },
  );

  it('passes every piece of Japanese UI text through the translator', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    const untranslated: string[] = [];
    for (const [path, source] of Object.entries(sources)) {
      source.split('\n').forEach((line, index) => {
        let rest = line.replace(/(?<![\w.])(?:t|msg)\('(?:[^'\\]|\\.)*'/g, '');
        for (const marker of internalMarkers) rest = rest.replace(`'${marker}'`, '');
        if (JAPANESE.test(rest)) untranslated.push(`${path}:${index + 1}`);
      });
    }
    expect(untranslated).toEqual([]);
  });
});
