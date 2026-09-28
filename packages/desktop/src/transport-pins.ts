import { createHash, X509Certificate } from 'node:crypto';

export type TransportPins = Readonly<Record<string, readonly string[]>>;
export function parseTransportPins(input: unknown, requireConfigured = true): TransportPins {
  const value = input as { version?: unknown; hosts?: unknown } | null;
  if (!value || value.version !== 1 || !value.hosts || typeof value.hosts !== 'object'
    || Array.isArray(value.hosts)) throw new Error('INVALID_TRANSPORT_PINS');
  const hosts = Object.entries(value.hosts);
  if (hosts.length > 32 || (requireConfigured && !hosts.length)) throw new Error('TRANSPORT_PINS_REQUIRED');
  for (const [host, pins] of hosts) {
    if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(host)
      || !Array.isArray(pins) || pins.length < 2 || pins.length > 8
      || new Set(pins).size !== pins.length
      || pins.some((pin) => typeof pin !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(pin)
        || Buffer.from(pin, 'base64').toString('base64') !== pin)) throw new Error('INVALID_TRANSPORT_PINS');
  }
  return Object.freeze(Object.fromEntries(hosts.map(([host, pins]) => [host, Object.freeze([...pins as string[]])])));
}

export function matchesTransportPin(host: string, certificatePem: string, pins: TransportPins): boolean {
  try {
    const cert = new X509Certificate(certificatePem);
    const digest = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
    return pins[host]?.includes(digest) ?? false;
  } catch { return false; }
}
