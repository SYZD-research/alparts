import assert from 'node:assert/strict';
import { createServer, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

// A minimal SMTP endpoint that accepts one message at a time and records it.
const messages: Array<{ from: string; to: string[]; data: string }> = [];
const sockets = new Set<Socket>();
const server = createServer((socket) => {
  sockets.add(socket);
  socket.once('close', () => sockets.delete(socket));
  let buffer = '';
  let inData = false;
  let current = { from: '', to: [] as string[], data: '' };
  socket.write('220 test ESMTP\r\n');
  socket.on('data', (chunk: Buffer) => {
    buffer += chunk.toString('utf8');
    for (let end = buffer.indexOf('\r\n'); end >= 0; end = buffer.indexOf('\r\n')) {
      const line = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      if (inData) {
        if (line === '.') {
          inData = false;
          messages.push(current);
          current = { from: '', to: [], data: '' };
          socket.write('250 queued\r\n');
        } else {
          current.data += `${line}\n`;
        }
        continue;
      }
      const verb = line.slice(0, 4).toUpperCase();
      if (verb === 'EHLO' || verb === 'HELO') socket.write('250 test\r\n');
      else if (verb === 'MAIL') { current.from = line; socket.write('250 ok\r\n'); }
      else if (verb === 'RCPT') { current.to.push(line); socket.write('250 ok\r\n'); }
      else if (verb === 'DATA') { inData = true; socket.write('354 go ahead\r\n'); }
      else if (verb === 'QUIT') { socket.write('221 bye\r\n'); socket.end(); }
      else socket.write('250 ok\r\n');
    }
  });
});

let email: typeof import('./email.service.js');

before(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
  process.env.S3_ACCESS_KEY ||= 'test-access-key';
  process.env.S3_SECRET_KEY ||= 'test-secret-key';
  process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
  process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
  process.env.SMTP_HOST = '127.0.0.1';
  process.env.SMTP_PORT = String((server.address() as AddressInfo).port);
  process.env.SMTP_FROM = 'no-reply@example.test';
  process.env.SMTP_TIMEOUT_MS = '2000';
  email = await import('./email.service.js');
});

after(() => {
  for (const socket of sockets) socket.destroy();
  server.close();
});

describe('email delivery', () => {
  it('sends through the configured SMTP server from the configured address', async () => {
    assert.equal(email.emailDelivery(), 'smtp');
    await email.sendEmail({ to: 'person@example.test', subject: 'Code', text: 'Your code is 123456' });
    const message = messages.at(-1)!;
    assert.match(message.from, /no-reply@example\.test/);
    assert.deepEqual(message.to.map((line) => line.match(/<(.+)>/)?.[1]), ['person@example.test']);
    assert.match(message.data, /Your code is 123456/);
    assert.equal(email.developmentEmails().length, 0, 'nothing is kept in memory once SMTP is set');
  });
});
