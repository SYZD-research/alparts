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
  it('rejects script, data and other active schemes in any spelling', () => {
    for (const href of [
      'javascript:alert(1)',
      'JavaScript:alert(1)',
      ' javascript:alert(1)',
      'java\tscript:alert(1)',
      'java\nscript:alert(1)',
      'vbscript:msgbox(1)',
      'data:text/html,<script>alert(1)</script>',
      'file:///etc/passwd',
      'blob:https://example.org/uuid',
    ]) {
      expect(safeMarkdownHref(href), href).toBeNull();
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
