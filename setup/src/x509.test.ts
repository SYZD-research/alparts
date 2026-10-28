import assert from 'node:assert/strict';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { connect as tlsConnect, createServer as createTlsServer } from 'node:tls';
import { test } from 'node:test';
import { createCertificateAuthority, daysUntilExpiry, der, derInteger, derOid, derTime, generatePrivateKeyPem, issueServerCertificate, spkiPin } from './x509.ts';

test('DER primitives encode as X.509 expects', () => {
  assert.equal(derOid('1.2.840.10045.4.3.2').toString('hex'), '06082a8648ce3d040302');
  assert.equal(derOid('2.5.29.19').toString('hex'), '0603551d13');
  assert.equal(derInteger(Buffer.from([0x00, 0x00, 0x7f])).toString('hex'), '02017f');
  assert.equal(derInteger(Buffer.from([0x80])).toString('hex'), '02020080');
  assert.equal(derTime(new Date('2030-01-02T03:04:05Z')).toString('ascii').slice(2), '300102030405Z');
  assert.equal(derTime(new Date('2051-01-02T03:04:05Z')).toString('ascii').slice(2), '20510102030405Z');
  assert.equal(der(0x04, Buffer.alloc(200)).subarray(0, 3).toString('hex'), '0481c8');
});

test('the authority and server certificates parse, chain and name the host', () => {
  const now = new Date('2026-10-27T00:00:00Z');
  const authority = createCertificateAuthority('Alparts internal CA', 7300, now);
  const ca = new X509Certificate(authority.certificatePem);
  assert.equal(ca.ca, true);
  assert.equal(ca.subject, 'CN=Alparts internal CA');
  assert.ok(ca.verify(ca.publicKey));

  const issued = issueServerCertificate(authority, { commonName: 'postgres', dnsNames: ['postgres'], validDays: 3650, now });
  const server = new X509Certificate(issued.certificatePem);
  assert.equal(server.ca, false);
  assert.equal(server.issuer, 'CN=Alparts internal CA');
  assert.ok(server.verify(ca.publicKey));
  assert.ok(server.checkIssued(ca));
  assert.equal(server.checkHost('postgres'), 'postgres');
  assert.equal(server.checkHost('object-storage'), undefined);
  assert.equal(server.subjectAltName, 'DNS:postgres');
  assert.equal(server.keyUsage?.includes('1.3.6.1.5.5.7.3.1'), true);
  assert.ok(server.checkPrivateKey(createPrivateKey(issued.privateKeyPem)));
  assert.ok(Math.abs(daysUntilExpiry(issued.certificatePem, now) - 3650) < 1);
});

test('a TLS client that trusts only the authority accepts the server certificate', async () => {
  const authority = createCertificateAuthority('Alparts internal CA', 30);
  const issued = issueServerCertificate(authority, { commonName: 'object-storage', dnsNames: ['object-storage'], validDays: 30 });
  const server = createTlsServer({ key: issued.privateKeyPem, cert: issued.certificatePem }, (socket) => socket.end('ok'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  try {
    const client = tlsConnect({ host: '127.0.0.1', port, servername: 'object-storage', ca: authority.certificatePem });
    await once(client, 'secureConnect');
    assert.equal(client.authorized, true);
    client.destroy();

    const wrongName = tlsConnect({ host: '127.0.0.1', port, servername: 'postgres', ca: authority.certificatePem });
    const [error] = await once(wrongName, 'error') as [NodeJS.ErrnoException];
    assert.equal(error.code, 'ERR_TLS_CERT_ALTNAME_INVALID');
  } finally {
    server.close();
  }
});

test('the pin of a key matches the pin of a certificate for that key', () => {
  const authority = createCertificateAuthority('Alparts internal CA', 30);
  const issued = issueServerCertificate(authority, { commonName: 'host', dnsNames: ['host'], validDays: 30 });
  const pin = spkiPin(issued.privateKeyPem);
  assert.match(pin, /^[A-Za-z0-9+/]{43}=$/);
  assert.equal(spkiPin(issued.certificatePem), pin);
  assert.notEqual(spkiPin(generatePrivateKeyPem()), pin);
});

test('server certificates refuse malformed names', () => {
  const authority = createCertificateAuthority('Alparts internal CA', 30);
  assert.throws(() => issueServerCertificate(authority, { commonName: 'x', dnsNames: ['Bad_Name'], validDays: 30 }));
  assert.throws(() => issueServerCertificate(authority, { commonName: 'x', dnsNames: [], validDays: 30 }));
});
