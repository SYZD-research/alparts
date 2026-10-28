import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { promises as dns } from 'node:dns';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer, get as httpGet } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { isIPv4 } from 'node:net';
import { networkInterfaces } from 'node:os';

export interface Cidr { base: number; prefix: number }

export function parseCidr(text: string): Cidr | null {
  const [address, prefixText = '32'] = text.split('/');
  if (!address || !isIPv4(address) || !/^\d{1,2}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > 32) return null;
  const value = address.split('.').reduce((total, part) => total * 256 + Number(part), 0);
  return { base: prefix === 0 ? 0 : value - (value % 2 ** (32 - prefix)), prefix };
}

function formatAddress(value: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join('.');
}

export function overlaps(a: Cidr, b: Cidr): boolean {
  const prefix = Math.min(a.prefix, b.prefix);
  const size = 2 ** (32 - prefix);
  return Math.floor(a.base / size) === Math.floor(b.base / size);
}

/**
 * Candidates for the private network between the proxy and the app. Uncommon
 * ranges first; each is used only when no route or Docker network overlaps it.
 */
export const EDGE_SUBNET_CANDIDATES = ['10.199.73.0/28', '10.211.89.0/28', '172.29.199.0/28', '192.168.199.0/28', '10.233.17.0/28'];

export interface EdgeNetwork {
  subnet: string;
  gateway: string;
  /** The proxy's fixed address: the only one the app trusts for client addresses. */
  proxyAddress: string;
  /** Where Docker assigns everything else, so it never takes the proxy's address. */
  dynamicRange: string;
}

export function edgeNetworkLayout(subnet: string): EdgeNetwork {
  const cidr = parseCidr(subnet);
  if (!cidr || cidr.prefix > 28) throw new Error(`Invalid edge subnet ${subnet}`);
  const half = 2 ** (32 - cidr.prefix) / 2;
  return {
    subnet: `${formatAddress(cidr.base)}/${cidr.prefix}`,
    gateway: formatAddress(cidr.base + 1),
    proxyAddress: formatAddress(cidr.base + 2),
    dynamicRange: `${formatAddress(cidr.base + half)}/${cidr.prefix + 1}`,
  };
}

export function chooseEdgeSubnet(taken: Cidr[]): string | null {
  for (const candidate of EDGE_SUBNET_CANDIDATES) {
    const cidr = parseCidr(candidate)!;
    if (!taken.some((used) => overlaps(used, cidr))) return candidate;
  }
  return null;
}

/** IPv4 routes from /proc/net/route, without the default route. */
export function parseProcRoutes(text: string): Cidr[] {
  const routes: Cidr[] = [];
  for (const line of text.split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 8) continue;
    const destination = littleEndianHex(fields[1]!);
    const mask = littleEndianHex(fields[7]!);
    if (destination === null || mask === null || mask === 0) continue;
    const prefix = mask.toString(2).replace(/0+$/, '').length;
    routes.push({ base: destination, prefix });
  }
  return routes;
}

function littleEndianHex(text: string): number | null {
  if (!/^[0-9A-Fa-f]{8}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'hex');
  return bytes.readUInt32LE(0);
}

export function hostRoutes(): Cidr[] {
  try {
    return parseProcRoutes(readFileSync('/proc/net/route', 'utf8'));
  } catch {
    return [];
  }
}

export interface ResolvedDomain { v4: string[]; v6: string[] }

export async function resolveDomain(domain: string): Promise<ResolvedDomain> {
  const lookup = async (query: () => Promise<string[]>) => {
    try {
      return await query();
    } catch {
      return [];
    }
  };
  const [v4, v6] = await Promise.all([lookup(() => dns.resolve4(domain)), lookup(() => dns.resolve6(domain))]);
  return { v4, v6 };
}

/** The addresses of this host's own interfaces, without loopback. */
export function localAddresses(): ResolvedDomain {
  const v4: string[] = [];
  const v6: string[] = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.internal) continue;
      if (entry.family === 'IPv4') v4.push(entry.address);
      else if (!entry.address.startsWith('fe80:')) v6.push(entry.address);
    }
  }
  return { v4, v6 };
}

export interface PortSpec { port: number; protocol: 'tcp' | 'udp'; host?: string }

/** The ports another program already uses. Binding to a low port needs root, which the setup has. */
export async function busyPorts(specs: PortSpec[]): Promise<PortSpec[]> {
  const busy: PortSpec[] = [];
  for (const spec of specs) {
    if (!(await portFree(spec))) busy.push(spec);
  }
  return busy;
}

async function portFree(spec: PortSpec): Promise<boolean> {
  const host = spec.host ?? '0.0.0.0';
  try {
    if (spec.protocol === 'tcp') {
      const server = createTcpServer();
      server.listen({ port: spec.port, host, exclusive: true });
      await once(server, 'listening');
      await new Promise<void>((resolve) => server.close(() => resolve()));
    } else {
      const socket = createSocket('udp4');
      socket.bind({ port: spec.port, address: host, exclusive: true });
      await once(socket, 'listening');
      await new Promise<void>((resolve) => socket.close(() => resolve()));
    }
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'EADDRINUSE';
  }
}

/**
 * Serves a random token on port 80 for a moment and fetches it through the
 * domain name: success shows that the name leads to this host and that port
 * 80 is open. Some networks cannot reach their own public address, so a
 * failure is only a hint.
 */
export async function reachesThisHost(domain: string, timeoutMs = 8000): Promise<boolean> {
  const token = randomBytes(16).toString('hex');
  const path = `/.well-known/alparts-setup/${token}`;
  const server = createHttpServer((request, response) => {
    response.writeHead(request.url === path ? 200 : 404, { 'content-type': 'text/plain' }).end(request.url === path ? token : '');
  });
  try {
    try {
      server.listen({ port: 80, host: '::' });
      await once(server, 'listening');
    } catch {
      server.listen({ port: 80, host: '0.0.0.0' });
      await once(server, 'listening');
    }
  } catch {
    return false;
  }
  try {
    return await new Promise<boolean>((resolve) => {
      const request = httpGet({ host: domain, port: 80, path, timeout: timeoutMs }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => { body += chunk; });
        response.on('end', () => resolve(response.statusCode === 200 && body === token));
      });
      request.on('timeout', () => request.destroy());
      request.on('error', () => resolve(false));
    });
  } finally {
    server.closeAllConnections();
    server.close();
  }
}
