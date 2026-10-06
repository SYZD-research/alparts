import type { IncomingMessage } from 'node:http';
import { isIPv4, isIPv6 } from 'node:net';
import proxyaddr from 'proxy-addr';
import { config } from '../config/index.js';
import { logWarning } from './logger.js';

// Express resolves req.ip with the same library and trust list, so HTTP and
// Socket.IO see the same client address behind a reverse proxy.
const trust: (address: string, hop: number) => boolean = config.network.trustedProxies.length > 0
  ? proxyaddr.compile([...config.network.trustedProxies])
  : () => false;

/** The client address of a raw request, honouring TRUSTED_PROXIES. */
export function requestClientAddress(request: IncomingMessage): string {
  try {
    return proxyaddr(request as Parameters<typeof proxyaddr>[0], trust) || 'unknown';
  } catch {
    return request.socket.remoteAddress || 'unknown';
  }
}

let untrustedForwardingReported = false;

/**
 * A request forwarded by a proxy while no proxy is trusted means every client
 * shares the proxy's address, and so one rate budget. Say so once.
 */
export function reportUntrustedForwarding(request: IncomingMessage): void {
  if (untrustedForwardingReported || config.network.trustedProxies.length > 0) return;
  if (request.headers['x-forwarded-for'] === undefined && request.headers.forwarded === undefined) return;
  untrustedForwardingReported = true;
  logWarning('network.forwarded_without_trusted_proxy', {
    outcome: 'warning',
    action: 'Set TRUSTED_PROXIES to the reverse proxy address so each client is rate-limited separately',
  });
}

function expandIPv6(address: string): string[] | null {
  const [head, tail, extra] = address.split('::');
  if (extra !== undefined) return null;
  const left = head ? head.split(':') : [];
  const right = tail !== undefined && tail ? tail.split(':') : [];
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? missing !== 0 : missing < 1) return null;
  return [...left, ...Array.from({ length: tail === undefined ? 0 : missing }, () => '0'), ...right];
}

/**
 * The key one client is counted under. One IPv6 host normally holds a whole
 * /64, so its addresses share one budget; IPv4-mapped addresses count as IPv4.
 */
export function rateLimitSource(address: string | undefined | null): string {
  if (!address) return 'unknown';
  const zoneless = address.split('%')[0]!.toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(zoneless);
  if (mapped && isIPv4(mapped[1]!)) return mapped[1]!;
  if (!isIPv6(zoneless)) return zoneless;
  const groups = expandIPv6(zoneless);
  if (!groups) return zoneless;
  return `${groups.slice(0, 4).map((group) => group.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}
