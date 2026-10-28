import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type AddressInfo, type Socket } from 'node:net';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { createServer as createTlsServer, TLSSocket } from 'node:tls';
import { checkSmtp } from './smtp.ts';
import { createCertificateAuthority, issueServerCertificate } from './x509.ts';

const authority = createCertificateAuthority('Test mail CA', 1);
const certificate = issueServerCertificate(authority, { commonName: 'localhost', dnsNames: ['localhost'], validDays: 1 });
const credentials = Buffer.from('\u0000mailer\u0000right-password').toString('base64');

/** A small mail server: EHLO, STARTTLS, AUTH PLAIN and QUIT. */
function converse(socket: Socket | TLSSocket, secure: boolean, onUpgrade: (socket: Socket) => void): void {
  let buffer = '';
  const onData = (chunk: Buffer) => {
    buffer += chunk.toString('utf8');
    let index: number;
    while ((index = buffer.indexOf('\r\n')) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      if (line.startsWith('EHLO')) {
        socket.write(secure ? '250-mail.test\r\n250 AUTH LOGIN PLAIN\r\n' : '250-mail.test\r\n250-STARTTLS\r\n250 SIZE 1000\r\n');
      } else if (line === 'STARTTLS') {
        socket.write('220 go ahead\r\n');
        socket.removeListener('data', onData);
        onUpgrade(socket as Socket);
        return;
      } else if (line.startsWith('AUTH PLAIN ')) {
        socket.write(line.slice(11) === credentials ? '235 ok\r\n' : '535 no\r\n');
      } else if (line === 'QUIT') {
        socket.end('221 bye\r\n');
      } else {
        socket.write('502 unknown\r\n');
      }
    }
  };
  socket.on('data', onData);
  socket.on('error', () => undefined);
}

async function startServer(mode: 'starttls' | 'tls'): Promise<{ port: number; close: () => void }> {
  const upgrade = (plain: Socket) => {
    const secure = new TLSSocket(plain, { isServer: true, key: certificate.privateKeyPem, cert: certificate.certificatePem });
    converse(secure, true, () => undefined);
  };
  const server = mode === 'starttls'
    ? createServer((socket) => {
      socket.write('220 mail.test ready\r\n');
      converse(socket, false, upgrade);
    })
    : createTlsServer({ key: certificate.privateKeyPem, cert: certificate.certificatePem }, (socket) => {
      socket.write('220 mail.test ready\r\n');
      converse(socket, true, () => undefined);
    });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

test('STARTTLS with a verified certificate and a correct password succeeds', async () => {
  const server = await startServer('starttls');
  try {
    const result = await checkSmtp({ host: 'localhost', port: server.port, security: 'starttls', user: 'mailer', password: 'right-password', ca: authority.certificatePem });
    assert.deepEqual(result, { ok: true });
  } finally {
    server.close();
  }
});

test('a wrong password is reported as a sign-in failure', async () => {
  const server = await startServer('starttls');
  try {
    const result = await checkSmtp({ host: 'localhost', port: server.port, security: 'starttls', user: 'mailer', password: 'wrong', ca: authority.certificatePem });
    assert.equal(result.ok, false);
    assert.equal(!result.ok && result.reason, 'auth');
  } finally {
    server.close();
  }
});

test('an untrusted certificate is reported as a certificate problem', async () => {
  const server = await startServer('tls');
  try {
    const result = await checkSmtp({ host: 'localhost', port: server.port, security: 'tls', user: null, password: null });
    assert.equal(!result.ok && result.reason, 'tls');
  } finally {
    server.close();
  }
});

test('implicit TLS without a user connects and stops before sending anything', async () => {
  const server = await startServer('tls');
  try {
    const result = await checkSmtp({ host: 'localhost', port: server.port, security: 'tls', user: null, password: null, ca: authority.certificatePem });
    assert.deepEqual(result, { ok: true });
  } finally {
    server.close();
  }
});

test('a closed port is reported as a connection problem', async () => {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  server.close();
  const result = await checkSmtp({ host: '127.0.0.1', port, security: 'starttls', user: null, password: null, timeoutMs: 2000 });
  assert.equal(!result.ok && result.reason, 'connect');
});

test('a server that takes the connection and never answers is given up on in time', async () => {
  const held: Socket[] = [];
  const server = createServer((socket) => void held.push(socket));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  try {
    // With implicit TLS the handshake never ends; with STARTTLS the greeting never comes.
    for (const security of ['tls', 'starttls'] as const) {
      const check = checkSmtp({ host: '127.0.0.1', port, security, user: null, password: null, timeoutMs: 300 });
      const result = await Promise.race([check, sleep(5000).then(() => 'still waiting' as const)]);
      assert.notEqual(result, 'still waiting', security);
      assert.equal(result !== 'still waiting' && !result.ok && result.reason, 'connect', security);
    }
  } finally {
    // Ends a check that would otherwise wait for ever.
    for (const socket of held) socket.destroy();
    server.close();
  }
});
