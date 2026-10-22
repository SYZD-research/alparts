import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { describeLink } from '../../services/link-destination';
import { translate } from '../../i18n';
import { OpenLinkDialog } from './MessageLink';

function confirmation(text: string, href = 'https://evil.example/phish?a=1') {
  const destination = describeLink(href, text, 'https://chat.example.test/')!;
  return renderToStaticMarkup(
    <OpenLinkDialog open onClose={() => undefined} text={text} destination={destination} />,
  );
}

describe('confirmation before opening a link', () => {
  it('names the real host and shows the whole address', () => {
    const html = confirmation('https://accounts.example.com/verify');

    expect(html).toContain('role="dialog"');
    expect(html).toContain('リンク先を確認してください');
    expect(html).toContain('このリンクは「https://accounts.example.com/verify」と表示されていますが、実際には evil.example を開きます。');
    expect(html).toContain('>https://evil.example/phish?a=1<');
    expect(html).toContain('信頼できる場合だけ開いてください。');
  });

  it('opens the link only from its own button, like any other link', () => {
    const html = confirmation('accounts.example.com');

    expect(html).toContain('>キャンセル<');
    expect(html).toMatch(/<a href="https:\/\/evil\.example\/phish\?a=1" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" tabindex="0"[^>]*>開く<\/a>/);
    // The cancel button comes first, so the dialog opens with the safe choice in reach.
    expect(html.indexOf('>キャンセル<')).toBeLessThan(html.indexOf('>開く<'));
  });

  it('cannot be reordered by direction marks in the link text', () => {
    // A right-to-left override (U+202E) and its end (U+202C) inside the text the dialog quotes.
    const html = confirmation('https://accounts.example.com\u{202e}/live/\u{202c}verify');

    expect(html).not.toMatch(/[\u{202a}-\u{202e}\u{2066}-\u{2069}]/u);
    expect(html).toContain('「https://accounts.example.com /live/ verify」');
  });

  it('shortens very long text', () => {
    const html = confirmation(`https://accounts.example.com/${'a'.repeat(300)}`);

    expect(html).toContain('…」');
    expect(html).not.toContain('a'.repeat(100));
  });

  it('is written in English too', () => {
    // Static rendering always uses the initial language, so the English texts are read from the catalog.
    expect(translate('en', 'リンク先を確認してください')).toBe('Check where this link goes');
    expect(translate('en', 'このリンクは「{text}」と表示されていますが、実際には {place} を開きます。', {
      text: 'https://accounts.example.com/verify',
      place: 'evil.example',
    })).toBe('This link says "https://accounts.example.com/verify", but it opens evil.example.');
    expect(translate('en', '信頼できる場合だけ開いてください。')).toBe('Open it only if you trust it.');
    expect(translate('en', '開く')).toBe('Open');
    expect(translate('en', 'リンク先: {address}', { address: 'https://evil.example/' })).toBe('Destination: https://evil.example/');
  });
});
