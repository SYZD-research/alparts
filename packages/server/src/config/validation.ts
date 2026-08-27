import { isIP } from 'node:net';
import type { VoiceIceServer } from '@alparts/shared';

export function parseBindHost(configured: string | undefined): string {
  const host = configured?.trim() || '127.0.0.1';
  if (isIP(host) === 0) {
    throw new Error('BIND_HOST must be an IPv4 or IPv6 literal');
  }
  return host;
}

export function parseBoundedInteger(
  name: string,
  configured: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = configured?.trim() || String(fallback);
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

export function parseCorsOrigins(configured: string, isProduction: boolean): string[] {
  const entries = configured.split(',').map((origin) => origin.trim()).filter(Boolean);
  if (entries.length < 1 || entries.length > 32) {
    throw new Error('CORS_ORIGINS must contain between 1 and 32 exact origins');
  }

  const origins = entries.map((entry) => {
    if (entry.length > 2048 || entry === '*') throw new Error('CORS_ORIGINS contains an invalid origin');
    let parsed: URL;
    try {
      parsed = new URL(entry);
    } catch {
      throw new Error('CORS_ORIGINS contains an invalid URL');
    }
    if (
      !['http:', 'https:'].includes(parsed.protocol)
      || parsed.username
      || parsed.password
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
      || parsed.origin !== entry
    ) {
      throw new Error('CORS_ORIGINS entries must be exact HTTP(S) origins without credentials or paths');
    }
    const isLoopback = parsed.hostname === 'localhost'
      || parsed.hostname === '127.0.0.1'
      || parsed.hostname === '[::1]';
    if (isProduction && parsed.protocol !== 'https:' && !isLoopback) {
      throw new Error('Production CORS origins must use HTTPS unless they are loopback-only');
    }
    return parsed.origin;
  });

  if (new Set(origins).size !== origins.length) {
    throw new Error('CORS_ORIGINS must not contain duplicate origins');
  }
  return origins;
}

export function parseVoiceIceServers(configured: string | undefined): VoiceIceServer[] {
  const raw = configured?.trim();
  if (!raw) return [];
  if (Buffer.byteLength(raw, 'utf8') > 16 * 1024) {
    throw new Error('VOICE_ICE_SERVERS_JSON is too large');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('VOICE_ICE_SERVERS_JSON must be valid JSON');
  }
  if (!Array.isArray(parsed) || parsed.length > 4) {
    throw new Error('VOICE_ICE_SERVERS_JSON must be an array of at most 4 ICE servers');
  }
  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`VOICE_ICE_SERVERS_JSON[${index}] must be an object`);
    }
    const candidate = entry as Record<string, unknown>;
    if (Object.keys(candidate).some((key) => !['urls', 'username', 'credential'].includes(key))) {
      throw new Error(`VOICE_ICE_SERVERS_JSON[${index}] contains an unsupported field`);
    }
    const rawUrls = typeof candidate.urls === 'string' ? [candidate.urls] : candidate.urls;
    if (!Array.isArray(rawUrls) || rawUrls.length < 1 || rawUrls.length > 4) {
      throw new Error(`VOICE_ICE_SERVERS_JSON[${index}].urls must contain 1 to 4 URLs`);
    }
    const urls = rawUrls.map((url) => {
      if (
        typeof url !== 'string'
        || url.length < 1
        || url.length > 512
        || /[\s\u0000-\u001f\u007f@]/.test(url)
        || !/^(?:stun|stuns|turn|turns):[^?#]+(?:\?transport=(?:udp|tcp))?$/i.test(url)
      ) throw new Error(`VOICE_ICE_SERVERS_JSON[${index}] contains an invalid ICE URL`);
      return url;
    });
    const username = optionalIceCredential(candidate.username, index, 'username');
    const credential = optionalIceCredential(candidate.credential, index, 'credential');
    if ((username === undefined) !== (credential === undefined)) {
      throw new Error(`VOICE_ICE_SERVERS_JSON[${index}] must configure username and credential together`);
    }
    if (urls.some((url) => /^turns?:/i.test(url)) && (!username || !credential)) {
      throw new Error(`VOICE_ICE_SERVERS_JSON[${index}] TURN URLs require credentials`);
    }
    return {
      urls,
      ...(username === undefined ? {} : { username, credential: credential! }),
    };
  });
}

function optionalIceCredential(
  value: unknown,
  index: number,
  field: 'username' | 'credential',
): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 256
    || /[\u0000-\u001f\u007f]/.test(value)
  ) throw new Error(`VOICE_ICE_SERVERS_JSON[${index}].${field} is invalid`);
  return value;
}
