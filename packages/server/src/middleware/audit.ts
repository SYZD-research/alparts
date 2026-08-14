import { db } from '../db/index.js';
import { auditLogs } from '../db/schema.js';
import { createHash } from 'crypto';

interface AuditEntry {
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
}

let lastHash: string | null = null;

async function getLastHash(): Promise<string | null> {
  if (lastHash) return lastHash;
  const result = await db.query.auditLogs.findFirst({
    orderBy: (logs, { desc }) => desc(logs.createdAt),
  });
  lastHash = result?.hash ?? null;
  return lastHash;
}

function computeHash(data: string, prevHash: string | null): string {
  const content = `${prevHash || ''}:${data}`;
  return createHash('sha256').update(content).digest('hex');
}

export async function audit(entry: AuditEntry): Promise<void> {
  const prev = await getLastHash();
  const data = JSON.stringify({
    actorId: entry.actorId,
    action: entry.action,
    targetType: entry.targetType,
    targetId: entry.targetId,
    details: entry.details,
    timestamp: new Date().toISOString(),
  });

  const hash = computeHash(data, prev);

  await db.insert(auditLogs).values({
    actorId: entry.actorId || null,
    action: entry.action,
    targetType: entry.targetType || null,
    targetId: entry.targetId || null,
    details: entry.details || null,
    prevHash: prev,
    hash,
  });

  lastHash = hash;
}
