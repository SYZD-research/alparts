import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from 'node:crypto';

// A private certificate authority for the connections between the containers
// (the app to PostgreSQL and to the object store). Node can parse certificates
// but not write them, so this encodes the few DER structures X.509 needs.

const OID = {
  commonName: '2.5.4.3',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extendedKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  subjectAltName: '2.5.29.17',
  subjectKeyIdentifier: '2.5.29.14',
  authorityKeyIdentifier: '2.5.29.35',
} as const;

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const sequence = (...items: Buffer[]) => der(0x30, ...items);

/** A non-negative INTEGER from big-endian bytes. */
export function derInteger(value: Buffer): Buffer {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start += 1;
  const minimal = value.subarray(start);
  return der(0x02, (minimal[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), minimal]) : minimal);
}

function base128(value: number): number[] {
  const bytes = [value % 128];
  for (let rest = Math.floor(value / 128); rest > 0; rest = Math.floor(rest / 128)) bytes.unshift((rest % 128) | 0x80);
  return bytes;
}

export function derOid(dotted: string): Buffer {
  const arcs = dotted.split('.').map(Number);
  if (arcs.length < 2 || arcs.some((arc) => !Number.isSafeInteger(arc) || arc < 0)) throw new Error(`Invalid OID ${dotted}`);
  const [first, second, ...rest] = arcs as [number, number, ...number[]];
  return der(0x06, Buffer.from([...base128(first * 40 + second), ...rest.flatMap(base128)]));
}

/** UTCTime until 2049, GeneralizedTime from 2050 (RFC 5280, 4.1.2.5). */
export function derTime(date: Date): Buffer {
  const iso = date.toISOString();
  const digits = iso.slice(0, 19).replace(/[-:T]/g, '');
  return date.getUTCFullYear() < 2050
    ? der(0x17, Buffer.from(`${digits.slice(2)}Z`, 'ascii'))
    : der(0x18, Buffer.from(`${digits}Z`, 'ascii'));
}

function name(commonName: string): Buffer {
  return sequence(der(0x31, sequence(derOid(OID.commonName), der(0x0c, Buffer.from(commonName, 'utf8')))));
}

function extension(id: string, critical: boolean, value: Buffer): Buffer {
  return sequence(derOid(id), ...(critical ? [der(0x01, Buffer.from([0xff]))] : []), der(0x04, value));
}

/** A BIT STRING of named bits, with the trailing zero bits removed as DER requires. */
function namedBits(bits: number[]): Buffer {
  const highest = Math.max(...bits);
  const bytes = Buffer.alloc(Math.floor(highest / 8) + 1);
  for (const bit of bits) bytes[Math.floor(bit / 8)]! |= 0x80 >> (bit % 8);
  return der(0x03, Buffer.from([7 - (highest % 8)]), bytes);
}

function keyIdentifier(publicKey: KeyObject): Buffer {
  // RFC 7093 method: a truncated SHA-256 of the public key.
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest().subarray(0, 20);
}

export interface IssuedCertificate {
  certificatePem: string;
  privateKeyPem: string;
}

export type CertificateAuthority = IssuedCertificate;

interface CertificateRequest {
  subject: string;
  publicKey: KeyObject;
  issuer: { name: string; privateKey: KeyObject; keyIdentifier: Buffer } | null;
  ca: boolean;
  dnsNames: string[];
  validDays: number;
  now: Date;
}

function encodeCertificate(request: CertificateRequest, selfKey: KeyObject): string {
  const subjectKeyIdentifier = keyIdentifier(request.publicKey);
  const issuerName = request.issuer?.name ?? request.subject;
  const signingKey = request.issuer?.privateKey ?? selfKey;
  const authorityKey = request.issuer?.keyIdentifier ?? subjectKeyIdentifier;
  const serial = randomBytes(16);
  serial[0] = (serial[0]! & 0x7f) | 0x01;
  // An hour of tolerance for clocks that run slightly behind.
  const notBefore = new Date(request.now.getTime() - 60 * 60 * 1000);
  const notAfter = new Date(request.now.getTime() + request.validDays * 24 * 60 * 60 * 1000);

  const extensions = [
    extension(OID.basicConstraints, true, request.ca ? sequence(der(0x01, Buffer.from([0xff])), derInteger(Buffer.from([0]))) : sequence()),
    // keyCertSign (5) and cRLSign (6) for the authority, digitalSignature (0) for servers.
    extension(OID.keyUsage, true, request.ca ? namedBits([5, 6]) : namedBits([0])),
    extension(OID.subjectKeyIdentifier, false, der(0x04, subjectKeyIdentifier)),
    extension(OID.authorityKeyIdentifier, false, sequence(der(0x80, authorityKey))),
  ];
  if (!request.ca) {
    extensions.push(extension(OID.extendedKeyUsage, false, sequence(derOid(OID.serverAuth))));
    extensions.push(extension(OID.subjectAltName, false, sequence(
      ...request.dnsNames.map((dnsName) => der(0x82, Buffer.from(dnsName, 'ascii'))),
    )));
  }

  const algorithm = sequence(derOid(OID.ecdsaWithSha256));
  const tbs = sequence(
    der(0xa0, derInteger(Buffer.from([2]))),
    derInteger(serial),
    algorithm,
    name(issuerName),
    sequence(derTime(notBefore), derTime(notAfter)),
    name(request.subject),
    request.publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, sequence(...extensions)),
  );
  // Node signs EC keys with the DER-encoded ECDSA-Sig-Value X.509 expects.
  const signature = sign('sha256', tbs, signingKey);
  const certificate = sequence(tbs, algorithm, der(0x03, Buffer.from([0]), signature));
  const lines = certificate.toString('base64').match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function newKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

export function exportPrivateKey(privateKey: KeyObject): string {
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/** A fresh P-256 key, as PKCS#8 PEM. */
export function generatePrivateKeyPem(): string {
  return exportPrivateKey(newKeyPair().privateKey);
}

export function createCertificateAuthority(commonName: string, validDays: number, now = new Date()): CertificateAuthority {
  const { publicKey, privateKey } = newKeyPair();
  const certificatePem = encodeCertificate({
    subject: commonName, publicKey, issuer: null, ca: true, dnsNames: [], validDays, now,
  }, privateKey);
  return { certificatePem, privateKeyPem: exportPrivateKey(privateKey) };
}

export function issueServerCertificate(
  authority: CertificateAuthority,
  options: { commonName: string; dnsNames: string[]; validDays: number; now?: Date },
): IssuedCertificate {
  if (options.dnsNames.length === 0) throw new Error('A server certificate needs a DNS name');
  for (const dnsName of options.dnsNames) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(dnsName)) {
      throw new Error(`Invalid DNS name ${dnsName}`);
    }
  }
  const authorityCertificate = new X509Certificate(authority.certificatePem);
  const authorityKey = createPrivateKey(authority.privateKeyPem);
  const { publicKey, privateKey } = newKeyPair();
  const certificatePem = encodeCertificate({
    subject: options.commonName,
    publicKey,
    issuer: {
      name: authorityCertificate.subject.replace(/^CN=/, ''),
      privateKey: authorityKey,
      keyIdentifier: keyIdentifier(authorityCertificate.publicKey),
    },
    ca: false,
    dnsNames: options.dnsNames,
    validDays: options.validDays,
    now: options.now ?? new Date(),
  }, privateKey);
  return { certificatePem, privateKeyPem: exportPrivateKey(privateKey) };
}

/**
 * The SHA-256 of a public key's SubjectPublicKeyInfo in standard Base64, the
 * format of the desktop and Android transport pins. Accepts a certificate or
 * a private key in PEM.
 */
export function spkiPin(pem: string): string {
  const publicKey = pem.includes('CERTIFICATE') ? new X509Certificate(pem).publicKey : createPublicKey(createPrivateKey(pem));
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
}

/** Days until the certificate expires (negative once it has). */
export function daysUntilExpiry(certificatePem: string, now = new Date()): number {
  const certificate = new X509Certificate(certificatePem);
  return (Date.parse(certificate.validTo) - now.getTime()) / (24 * 60 * 60 * 1000);
}
