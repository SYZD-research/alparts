import type { AuditLogEntry } from '../services/api';

export interface SafeAuditDetail {
  key: string;
  value: string;
}

const ALLOWED_DETAIL_KEYS = new Set([
  'result', 'reason', 'workspaceId', 'channelId', 'messageId', 'userId',
  'memberId', 'roleId', 'deviceId', 'sessionId', 'invitationId', 'attachmentId',
  'uploadId', 'version', 'recipientCount', 'resultCount', 'paginated', 'changed',
  'requiresKeyRotation', 'valid', 'checkpoint', 'chunkCount', 'ciphertextSizeBytes',
  'plaintextSizeBytes', 'expiresAt', 'name', 'position', 'action',
]);
const SECRET_LIKE_KEY = /token|secret|password|credential|cookie|authorization|content|nonce|signature|hash|private|identitykey|encryptedkey|wrappedkey|email|ip|useragent/i;

export function safeAuditDetails(details: unknown): SafeAuditDetail[] {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return [];
  const entries: SafeAuditDetail[] = [];
  for (const [key, value] of Object.entries(details as Record<string, unknown>)) {
    if (!ALLOWED_DETAIL_KEYS.has(key) || SECRET_LIKE_KEY.test(key)) continue;
    const formatted = formatSafeScalar(value);
    if (formatted !== null) entries.push({ key, value: formatted });
  }
  return entries;
}

export function auditResult(entry: Pick<AuditLogEntry, 'details'>): 'success' | 'failure' | 'unknown' {
  if (!entry.details || typeof entry.details !== 'object' || Array.isArray(entry.details)) return 'unknown';
  const result = (entry.details as Record<string, unknown>).result;
  return result === 'success' || result === 'failure' ? result : 'unknown';
}

function formatSafeScalar(value: unknown): string | null {
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return normalized ? normalized.slice(0, 160) : null;
}
