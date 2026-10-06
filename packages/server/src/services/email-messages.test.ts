import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { emailLocale, existingAccountEmail, registrationCodeEmail } from './email-messages.js';

describe('registration email language', () => {
  it('follows the first supported language the client asks for', () => {
    assert.equal(emailLocale('ja'), 'ja');
    assert.equal(emailLocale('ja-JP,en;q=0.8'), 'ja');
    assert.equal(emailLocale('en-GB,ja;q=0.9'), 'en');
    assert.equal(emailLocale('fr-FR,ja;q=0.5,en;q=0.4'), 'ja');
  });

  it('ranks by quality before order and skips refused languages', () => {
    assert.equal(emailLocale('en;q=0.2,ja;q=0.9'), 'ja');
    assert.equal(emailLocale('ja;q=0,en'), 'en');
  });

  it('falls back to English', () => {
    assert.equal(emailLocale(undefined), 'en');
    assert.equal(emailLocale(''), 'en');
    assert.equal(emailLocale('de-DE,fr'), 'en');
  });

  it('puts the code in the message in both languages', () => {
    for (const locale of ['ja', 'en'] as const) {
      assert.match(registrationCodeEmail(locale, '012345').text, /\n012345\n/);
      assert.ok(existingAccountEmail(locale).subject.includes('alparts'));
    }
    assert.match(registrationCodeEmail('en', '012345').subject, /verification code/);
    assert.match(registrationCodeEmail('ja', '012345').subject, /確認コード/);
  });
});
