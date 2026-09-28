import { describe, expect, it } from 'vitest';
import { safeMarkdownHref } from './url-policy';

describe('Markdown navigation policy', () => {
  it('rejects network-path references and browser backslash normalization', () => {
    for (const href of [
      '//evil.example',
      '  //evil.example ',
      '\\\\evil.example',
      '/\\evil.example',
      '\\evil.example',
      '\n//evil.example',
      'https:\\\\evil.example',
    ]) {
      expect(safeMarkdownHref(href)).toBeNull();
    }
  });
  it('preserves explicit web/mail links and local paths', () => {
    for (const href of [
      'https://example.org/a',
      'http://example.org',
      'mailto:a@example.org',
      '/help',
      '../help',
      '#section',
    ]) {
      expect(safeMarkdownHref(href)).toBe(href);
    }
  });
});
