import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { isIPv4 } from 'node:net';
import { domainToASCII } from 'node:url';
import { dirname } from 'node:path';
import { ensureDirectory, writeFileAtomic } from './files.ts';

export type Language = 'ja' | 'en';

export type EmailSettings =
  | { mode: 'smtp'; host: string; port: number; security: 'starttls' | 'tls'; from: string; user: string | null }
  | { mode: 'disabled' };

export interface VoiceSettings {
  /** Calls go through the server's own media relay instead of directly between the participants. */
  relay: boolean;
  publicAddress: string | null;
  basePort: number;
  workers: number;
}

export interface BackupSettings {
  /** The public age recipient the backups are encrypted to; its identity stays off this server. */
  recipient: string;
  /** Local time of day, HH:MM. */
  time: string;
  retentionDays: number;
  minimumCopies: number;
}

export interface NetworkSettings {
  /** The private network between the proxy and the app, fixed so the app can trust the proxy's address. */
  edgeSubnet: string;
  proxyAddress: string;
  /** The loopback port the app is also published on, for checks from this host. */
  appPort: number;
}

export interface Settings {
  version: 1;
  language: Language;
  domain: string;
  acmeEmail: string | null;
  /** `local` serves certificates from the proxy's own authority, for trials without a public name. */
  certificates: 'public' | 'local';
  email: EmailSettings;
  voice: VoiceSettings;
  backup: BackupSettings | null;
  network: NetworkSettings;
  image: { tag: string | null; previousTag: string | null };
  auditHeadObjectKey: string;
  state: {
    /** `pending` from just before the first checkpoint is written, so an interrupted run finishes it. */
    audit: 'none' | 'pending' | 'initialized';
    completed: boolean;
    createdAt: string;
  };
}

export const DEFAULT_VOICE_PORT = 40000;
export const DEFAULT_APP_PORT = 3000;

/** A lower-case ASCII domain name, or null. Accepts Unicode names and a trailing dot. */
export function normalizeDomain(input: string): string | null {
  const trimmed = input.trim().replace(/\.$/, '');
  if (!trimmed || trimmed.includes('/') || trimmed.includes(':')) return null;
  const ascii = domainToASCII(trimmed.toLowerCase());
  if (!ascii || ascii.length > 253 || isIPv4(ascii)) return null;
  const labels = ascii.split('.');
  if (labels.length < 2 || /^[0-9]+$/.test(labels.at(-1)!)) return null;
  const valid = labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
  return valid ? ascii : null;
}

/** Same rule as the server's SMTP_FROM check. */
export function isEmailAddress(input: string): boolean {
  return input.length <= 254 && /^[^\s@<>"(),;:]+@[^\s@<>"(),;:]+\.[^\s@<>"(),;:]+$/.test(input);
}

export function isHostName(input: string): boolean {
  return isIPv4(input) || normalizeDomain(input) === input || /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(input);
}

export function isPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

/** Addresses that only reach a private network, so callers outside it cannot use them. */
export function isPrivateIPv4(address: string): boolean {
  const [a = 0, b = 0] = address.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || a === 0;
}

/** A hybrid post-quantum age recipient, as scripts/backup.sh requires. */
export function isAgeRecipient(input: string): boolean {
  return input.length <= 4096 && /^age1pq1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(input);
}

/** HH:MM in 24-hour time, or null. */
export function normalizeTime(input: string): string | null {
  const match = /^([01]?[0-9]|2[0-3]):([0-5][0-9])$/.exec(input.trim());
  return match ? `${match[1]!.padStart(2, '0')}:${match[2]}` : null;
}

export function newAuditHeadObjectKey(): string {
  return `alparts-${randomBytes(12).toString('hex')}`;
}

function fail(field: string): never {
  throw new Error(`The saved setup is invalid: ${field}`);
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(field);
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length > 4096) fail(field);
  return value;
}

function nullableText(value: unknown, field: string): string | null {
  return value === null ? null : text(value, field);
}

function integer(value: unknown, field: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) fail(field);
  return value;
}

/** Reads back what saveSettings wrote, refusing anything an edit could have broken. */
export function parseSettings(raw: unknown): Settings {
  const root = object(raw, 'settings');
  if (root.version !== 1) fail('version');
  const language = root.language === 'ja' || root.language === 'en' ? root.language : fail('language');
  const domain = text(root.domain, 'domain');
  if (normalizeDomain(domain) !== domain) fail('domain');
  const acmeEmail = nullableText(root.acmeEmail, 'acmeEmail');
  if (acmeEmail !== null && !isEmailAddress(acmeEmail)) fail('acmeEmail');
  const certificates = root.certificates === 'public' || root.certificates === 'local' ? root.certificates : fail('certificates');

  const emailRoot = object(root.email, 'email');
  let email: EmailSettings;
  if (emailRoot.mode === 'disabled') {
    email = { mode: 'disabled' };
  } else if (emailRoot.mode === 'smtp') {
    const host = text(emailRoot.host, 'email.host');
    const from = text(emailRoot.from, 'email.from');
    const user = nullableText(emailRoot.user, 'email.user');
    const security = emailRoot.security === 'starttls' || emailRoot.security === 'tls' ? emailRoot.security : fail('email.security');
    if (!isHostName(host)) fail('email.host');
    if (!isEmailAddress(from)) fail('email.from');
    if (user !== null && (!user || /[\r\n]/.test(user))) fail('email.user');
    email = { mode: 'smtp', host, port: integer(emailRoot.port, 'email.port', 1, 65535), security, from, user };
  } else {
    fail('email.mode');
  }

  const voiceRoot = object(root.voice, 'voice');
  if (typeof voiceRoot.relay !== 'boolean') fail('voice.relay');
  const publicAddress = nullableText(voiceRoot.publicAddress, 'voice.publicAddress');
  if (publicAddress !== null && !isIPv4(publicAddress)) fail('voice.publicAddress');
  if (voiceRoot.relay && publicAddress === null) fail('voice.publicAddress');
  const workers = integer(voiceRoot.workers, 'voice.workers', 1, 64);
  const voice: VoiceSettings = {
    relay: voiceRoot.relay,
    publicAddress,
    basePort: integer(voiceRoot.basePort, 'voice.basePort', 1024, 65535 - workers + 1),
    workers,
  };

  let backup: BackupSettings | null = null;
  if (root.backup !== null) {
    const backupRoot = object(root.backup, 'backup');
    const recipient = text(backupRoot.recipient, 'backup.recipient');
    if (!isAgeRecipient(recipient)) fail('backup.recipient');
    const time = normalizeTime(text(backupRoot.time, 'backup.time')) ?? fail('backup.time');
    backup = {
      recipient,
      time,
      retentionDays: integer(backupRoot.retentionDays, 'backup.retentionDays', 1, 3650),
      minimumCopies: integer(backupRoot.minimumCopies, 'backup.minimumCopies', 1, 1000),
    };
  }

  const networkRoot = object(root.network, 'network');
  const edgeSubnet = text(networkRoot.edgeSubnet, 'network.edgeSubnet');
  const proxyAddress = text(networkRoot.proxyAddress, 'network.proxyAddress');
  if (!/^\d+\.\d+\.\d+\.\d+\/(2[4-9]|30)$/.test(edgeSubnet) || !isIPv4(edgeSubnet.split('/')[0]!)) fail('network.edgeSubnet');
  if (!isIPv4(proxyAddress)) fail('network.proxyAddress');
  const network: NetworkSettings = {
    edgeSubnet,
    proxyAddress,
    appPort: integer(networkRoot.appPort, 'network.appPort', 1, 65535),
  };

  const imageRoot = object(root.image, 'image');
  const tag = nullableText(imageRoot.tag, 'image.tag');
  const previousTag = nullableText(imageRoot.previousTag, 'image.previousTag');
  for (const [field, value] of [['image.tag', tag], ['image.previousTag', previousTag]] as const) {
    if (value !== null && !isImageTag(value)) fail(field);
  }

  const auditHeadObjectKey = text(root.auditHeadObjectKey, 'auditHeadObjectKey');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(auditHeadObjectKey)) fail('auditHeadObjectKey');

  const stateRoot = object(root.state, 'state');
  const audit = stateRoot.audit === 'none' || stateRoot.audit === 'pending' || stateRoot.audit === 'initialized'
    ? stateRoot.audit : fail('state.audit');
  if (typeof stateRoot.completed !== 'boolean') fail('state.completed');

  return {
    version: 1,
    language,
    domain,
    acmeEmail,
    certificates,
    email,
    voice,
    backup,
    network,
    image: { tag, previousTag },
    auditHeadObjectKey,
    state: { audit, completed: stateRoot.completed, createdAt: text(stateRoot.createdAt, 'state.createdAt') },
  };
}

/** Docker tag syntax, as compose.production.yml's ALPARTS_IMAGE_TAG takes it. */
export function isImageTag(value: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(value);
}

export function loadSettings(file: string): Settings | null {
  if (!existsSync(file)) return null;
  return parseSettings(JSON.parse(readFileSync(file, 'utf8')));
}

export function saveSettings(file: string, settings: Settings): void {
  ensureDirectory(dirname(file), 0o700);
  writeFileAtomic(file, `${JSON.stringify(settings, null, 2)}\n`, 0o600);
}
