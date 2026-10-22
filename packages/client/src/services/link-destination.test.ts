import { describe, expect, it } from 'vitest';
import { describeLink, plainLinkText } from './link-destination';

const PAGE = 'https://chat.example.test/';
const describe_ = (href: string, text: string) => describeLink(href, text, PAGE);

describe('link destination', () => {
  it('shows the host of a link whose text says nothing about it', () => {
    expect(describe_('https://evil.example/phish?a=1', 'click here')).toEqual({
      place: 'evil.example',
      address: 'https://evil.example/phish?a=1',
      masked: true,
      misleading: false,
    });
    expect(describe_('https://evil.example/', 'こちら')).toMatchObject({ masked: true, misleading: false });
  });

  it('leaves plain autolinks alone, in the forms the Markdown parser writes them', () => {
    for (const [href, text] of [
      ['https://example.com/a?b=c', 'https://example.com/a?b=c'],
      ['https://example.com/', 'https://example.com'],
      ['http://www.example.com/path', 'www.example.com/path'],
      ['https://example.com/日本語', 'https://example.com/日本語'],
      ['https://日本語.jp/', 'https://日本語.jp/'],
      ['mailto:person@example.com', 'person@example.com'],
    ]) {
      expect(describe_(href, text), `${text} -> ${href}`).toMatchObject({ masked: false, misleading: false });
    }
  });

  it('asks about text that reads like another web address', () => {
    for (const text of [
      'https://accounts.example.com/verify',
      'HTTPS://ACCOUNTS.EXAMPLE.COM',
      'accounts.example.com',
      'www.example.com/login',
      'example.co.jp',
      'accounts.example.com:8443/login',
      'Sign in at https://bank.example.com/login now',
      'Check example.com (official)',
      'https://accounts.example.com/verifyを開く',
      // Full-width letters, written as code points so they stay visible in the source.
      String.fromCodePoint(0xff48, 0xff54, 0xff54, 0xff50, 0xff53, 0xff1a, 0xff0f, 0xff0f, 0xff45, 0xff58, 0xff41, 0xff4d, 0xff50, 0xff4c, 0xff45, 0xff0e, 0xff43, 0xff4f, 0xff4d),
      String.fromCodePoint(0xff57, 0xff57, 0xff57, 0xff0e, 0xff45, 0xff58, 0xff41, 0xff4d, 0xff50, 0xff4c, 0xff45, 0xff0e, 0xff43, 0xff4f, 0xff4d),
    ]) {
      const destination = describe_('https://evil.example/phish', text);
      expect(destination, text).toMatchObject({ place: 'evil.example', masked: true, misleading: true });
    }
  });

  it('asks about text that reads like another mail address, and about a mail link behind a web address', () => {
    expect(describe_('mailto:attacker@evil.example', 'support@bank.example.com')).toMatchObject({
      place: 'attacker@evil.example',
      masked: true,
      misleading: true,
    });
    expect(describe_('mailto:attacker@evil.example', 'write to us')).toMatchObject({ masked: true, misleading: false });
    expect(describe_('mailto:attacker@evil.example', 'www.example.com')).toMatchObject({ misleading: true });
    expect(describe_('mailto:team@example.com', 'team@example.com')).toMatchObject({ masked: false, misleading: false });
    expect(describe_('mailto:team@example.com', 'mail example.com')).toMatchObject({ masked: true, misleading: false });
  });

  it('does not ask about ordinary link text', () => {
    for (const text of [
      'click here',
      'the docs',
      'Read more',
      'こちらをクリック',
      'v1.2.3',
      'version 1.2.3.4',
      'e.g. this one',
      'README.md',
      'main.rs',
      'config.json',
      'Node.js',
      'build.sh',
      '3.5mm jack',
      'U.S.A.',
      'file.txt',
      '',
    ]) {
      expect(describe_('https://github.com/org/repo', text), text).toMatchObject({ misleading: false });
    }
  });

  it('does not ask when the text names the site the link goes to', () => {
    for (const [href, text] of [
      ['https://example.com/docs/intro', 'https://example.com/docs'],
      ['https://www.example.com/page', 'example.com'],
      ['https://example.com/page', 'www.example.com'],
      ['https://EXAMPLE.com/page', 'example.com/page'],
      ['https://example.com/page', 'Read it at example.com.'],
    ]) {
      expect(describe_(href, text), `${text} -> ${href}`).toMatchObject({ misleading: false });
    }
    // The host is still named beside the text, so the page can be recognised without hovering.
    expect(describe_('https://example.com/docs/intro', 'https://example.com/docs')).toMatchObject({ masked: true });
  });

  it('tells apart hosts that only look alike', () => {
    expect(describe_('https://accounts.example.com.evil.example/', 'accounts.example.com')).toMatchObject({
      place: 'accounts.example.com.evil.example',
      misleading: true,
    });
    expect(describe_('https://accounts.example.com@evil.example/', 'accounts.example.com')).toMatchObject({
      place: 'evil.example',
      misleading: true,
    });
    expect(describe_('https://example.com/', 'accounts.example.com')).toMatchObject({ misleading: true });
    expect(describe_('https://evil.example/', 'example.com.evil.xyz')).toMatchObject({ misleading: true });
    // A Cyrillic "a" in place of the Latin one: the host shown is the one the system really opens.
    expect(describe_('https://\u{430}pple.com/', 'https://apple.com')).toMatchObject({
      place: 'xn--pple-43d.com',
      misleading: true,
    });
  });

  it('keeps the destination the system opens, whatever the spelling', () => {
    expect(describe_('HTTPS://Evil.EXAMPLE:443/a b', 'x')).toMatchObject({
      place: 'evil.example',
      address: 'https://evil.example/a%20b',
    });
    // A zero-width space after the host does not change where the link goes.
    expect(describe_(' https://evil.example\u{200b}/', 'x')).toMatchObject({ place: 'evil.example' });
  });

  it('has nothing to say about links within the app', () => {
    expect(describe_('/help', 'https://accounts.example.com')).toBeNull();
    expect(describe_('../help', 'help')).toBeNull();
    expect(describe_('#section', 'section')).toBeNull();
    expect(describe_('https://chat.example.test/workspaces/1', 'a place in the app')).toBeNull();
    expect(describe_('https://chat.example.test.evil.example/', 'x')).toMatchObject({ masked: true });
  });

  it('reads only the start of very long text, quickly', () => {
    const started = performance.now();
    expect(describe_('https://evil.example/', `${'a.'.repeat(50_000)}com`)).toMatchObject({ masked: true });
    expect(describe_('https://evil.example/', `${'a'.repeat(100_000)}.com`)).toMatchObject({ masked: true });
    // The longest text that is read, written to make a pattern backtrack.
    expect(describe_('https://evil.example/', 'a-'.repeat(250))).toMatchObject({ misleading: false });
    expect(describe_('https://evil.example/', 'a.'.repeat(250))).toMatchObject({ misleading: false });
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe('link text in a confirmation', () => {
  it('drops control and direction marks and cuts long text', () => {
    // A right-to-left override (U+202E) and its end (U+202C) would reorder the words around them.
    expect(plainLinkText('a\u{202e}bc\u{202c} d\u{0}e\n f')).toBe('a bc d e f');
    expect(plainLinkText('x'.repeat(100), 10)).toBe(`${'x'.repeat(10)}…`);
    expect(plainLinkText('  short  ')).toBe('short');
  });
});
