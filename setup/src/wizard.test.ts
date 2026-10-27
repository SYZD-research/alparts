import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { SetupError } from './context.ts';
import { parseAnswersFile } from './wizard.ts';

function withFile(content: unknown, check: (path: string, dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-answers-'));
  try {
    const path = join(dir, 'answers.json');
    writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
    check(path, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('an answers file fills in defaults the way the questions do', () => {
  withFile({ domain: 'Chat.Example.com', email: { mode: 'disabled' } }, (path) => {
    assert.deepEqual(parseAnswersFile(path), {
      domain: 'chat.example.com',
      acmeEmail: null,
      certificates: 'public',
      email: { mode: 'disabled' },
      smtpPassword: null,
      voice: { relay: true, publicAddress: null },
      backup: null,
    });
  });
});

test('the SMTP password may come from its own file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'alparts-answers-'));
  try {
    writeFileSync(join(dir, 'smtp-password'), 'from-file\n');
    withFile({
      domain: 'chat.example.com',
      email: { mode: 'smtp', host: 'SMTP.example.com', security: 'tls', from: 'no-reply@example.com', user: 'mailer', passwordFile: join(dir, 'smtp-password') },
      voice: { relay: false },
      backup: { recipient: 'age1pq1qyqszqgp', time: '3:30' },
    }, (path) => {
      const answers = parseAnswersFile(path);
      assert.deepEqual(answers.email, { mode: 'smtp', host: 'smtp.example.com', port: 465, security: 'tls', from: 'no-reply@example.com', user: 'mailer' });
      assert.equal(answers.smtpPassword, 'from-file');
      assert.deepEqual(answers.backup, { recipient: 'age1pq1qyqszqgp', time: '03:30' });
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('invalid answers name the field', () => {
  const cases: Array<[unknown, string]> = [
    ['{not json', ''],
    [{ domain: 'localhost', email: { mode: 'disabled' } }, 'domain'],
    [{ domain: 'chat.example.com' }, 'email.mode'],
    [{ domain: 'chat.example.com', email: { mode: 'smtp', host: 'smtp.example.com', from: 'x', user: null } }, 'email.from'],
    [{ domain: 'chat.example.com', email: { mode: 'smtp', host: 'smtp.example.com', from: 'a@example.com', user: 'u' } }, 'email.password'],
    [{ domain: 'chat.example.com', email: { mode: 'disabled' }, voice: { relay: true, publicAddress: 'host' } }, 'voice.publicAddress'],
    [{ domain: 'chat.example.com', email: { mode: 'disabled' }, backup: { recipient: 'AGE-SECRET-KEY-1' } }, 'backup.recipient'],
  ];
  for (const [content, field] of cases) {
    withFile(content, (path) => {
      assert.throws(() => parseAnswersFile(path), (error: unknown) => error instanceof SetupError && (field === '' || error.values.field === field), field);
    });
  }
});
