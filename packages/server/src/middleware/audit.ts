import { withRuntimeFence } from '../security/runtime-lease.js';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { and, asc, desc, eq, gt, or, sql } from 'drizzle-orm';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { auditLogs } from '../db/schema.js';
import { BoundedAsyncGate } from '../security/bounded-async-gate.js';
import { AUDIT_COMMIT_WAIT_MS, MAX_PENDING_AUDIT_COMMITS } from '../security/limits.js';
import { currentLogContext } from '../security/log-context.js';
import { logError } from '../security/logger.js';
import { readWitnessFile, verifyAuditWitness, type AuditWitnessPayload } from '../security/audit-witness.js';

export interface AuditEntry {
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
}

interface AuditCheckpointV1 {
  version: 1;
  logId: string;
  logHash: string;
  updatedAt: string;
  signature: string;
}

interface AuditCheckpointV2 {
  version: 2;
  logId: string;
  logHash: string;
  logCreatedAt: string;
  updatedAt: string;
  signature: string;
}

type AuditCheckpoint = AuditCheckpointV1 | AuditCheckpointV2;

interface CommittedAuditEntry {
  id: string;
  hash: string;
  createdAt: Date;
}

let checkpointQueue: Promise<void> = Promise.resolve();
const auditCommitGate = new BoundedAsyncGate(1, MAX_PENDING_AUDIT_COMMITS, {
  busyError: 'AUDIT_UNAVAILABLE',
  timeoutError: 'AUDIT_UNAVAILABLE',
});
let checkpointFailure: Error | null = null;
let checkpointIntegrityFailure: Error | null = null;
let lastFullVerification: { valid: boolean; checkpoint: 'disabled' | 'initialized' | 'verified' } | null = null;
let lastAcceptedCheckpoint: AuditCheckpointV2 | null = null;
let externalWitness: { payload: AuditWitnessPayload; checkedAt: number } | null = null;

async function loadExternalWitness(): Promise<AuditWitnessPayload | null> {
  if (!config.audit.witnessPath) return null;
  if (externalWitness && Date.now() - externalWitness.checkedAt < 2_000
    && Date.parse(externalWitness.payload.expiresAt) > Date.now()) return externalWitness.payload;
  const payload = verifyAuditWitness(JSON.parse(await readWitnessFile(config.audit.witnessPath)),
    await readWitnessFile(config.audit.witnessPublicKeyPath!, 4096), config.audit.witnessDeploymentId!);
  if (externalWitness && Date.parse(payload.logCreatedAt) < Date.parse(externalWitness.payload.logCreatedAt)) {
    throw new Error('AUDIT_WITNESS_ROLLBACK');
  }
  if (externalWitness && payload.logCreatedAt === externalWitness.payload.logCreatedAt
    && (payload.logId !== externalWitness.payload.logId || payload.logHash !== externalWitness.payload.logHash)) {
    throw new Error('AUDIT_WITNESS_EQUIVOCATION');
  }
  externalWitness = { payload, checkedAt: Date.now() };
  return payload;
}

async function assertExternalWitness(): Promise<void> {
  const witness = await loadExternalWitness();
  if (!witness) return;
  const row = await db.query.auditLogs.findFirst({ where: eq(auditLogs.id, witness.logId) });
  if (!row || row.hash !== witness.logHash || row.createdAt.toISOString() !== witness.logCreatedAt) {
    throw new Error('AUDIT_WITNESS_MISSING_FROM_CHAIN');
  }
}

class AuditCheckpointIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditCheckpointIntegrityError';
  }
}

export class AuditUnavailableError extends Error {
  constructor(options?: ErrorOptions) {
    super('AUDIT_UNAVAILABLE', options);
    this.name = 'AuditUnavailableError';
  }
}

function computeHash(data: string, prevHash: string | null): string {
  return createHmac('sha256', config.audit.integrityKey)
    .update(prevHash || '', 'utf8')
    .update('\0', 'utf8')
    .update(data, 'utf8')
    .digest('hex');
}

function auditData(entry: {
  actorId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  details: unknown;
  createdAt: Date;
}): string {
  return canonicalJson([
    entry.actorId,
    entry.action,
    entry.targetType,
    entry.targetId,
    entry.details,
    entry.createdAt.toISOString(),
  ]);
}

function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
}

export function audit(entry: AuditEntry): Promise<void> {
  return appendStandaloneAudit(entry);
}

async function appendStandaloneAudit(entry: AuditEntry): Promise<void> {
  await withSerializedAuditCommit(async () => {
    await assertAuditCommitAdmission();
    const committed = await db.transaction((transaction) => appendAuditRow(transaction, entry));
    await enqueueCheckpoint(committed);
  });
}

/**
 * Commits a state change and its audit rows atomically. The independently
 * protected checkpoint is advanced immediately after commit; a checkpoint
 * failure makes readiness fail without misreporting the committed mutation as
 * rolled back.
 */
export async function auditedTransaction<T>(
  operation: (transaction: any) => Promise<T>,
  entries: (result: T) => AuditEntry | AuditEntry[],
): Promise<T> {
  return withSerializedAuditCommit(async () => {
    await assertAuditCommitAdmission();
    const committed = await db.transaction(async (transaction) => {
      const result = await operation(transaction);
      const definitions = entries(result);
      let checkpoint: CommittedAuditEntry | null = null;
      for (const entry of Array.isArray(definitions) ? definitions : [definitions]) {
        checkpoint = await appendAuditRow(transaction, entry);
      }
      if (!checkpoint) throw new Error('At least one audit entry is required');
      return { result, checkpoint };
    });
    try {
      await enqueueCheckpoint(committed.checkpoint);
    } catch (error) {
      // The state transaction and its chained audit row are already durable.
      // Report that committed result exactly once, but retain checkpointFailure
      // so the next mutation and readiness fail closed until operator recovery.
      logError('audit.checkpoint_write_failed_after_commit', error);
    }
    return committed.result;
  });
}

/**
 * Commits authoritative state that is intentionally not represented by its
 * own audit event, while sharing the exact admission/ordering boundary used
 * by audited mutations. This is reserved for high-frequency or provisional
 * state such as read cursors and resumable-upload chunk registrations.
 */
export async function auditGuardedTransaction<T>(
  operation: (transaction: any) => Promise<T>,
): Promise<T> {
  return withSerializedAuditCommit(async () => {
    await assertAuditCommitAdmission();
    return db.transaction(operation);
  });
}

/**
 * A best-effort preflight for an external side effect that must not begin once
 * an audit failure is known. The authoritative database commit must still use
 * auditedTransaction or auditGuardedTransaction because admission can change
 * after this function returns.
 */
export async function assertAuditWriteAvailable(): Promise<void> {
  await withSerializedAuditCommit(assertAuditCommitAdmission);
}

async function withSerializedAuditCommit<T>(operation: () => Promise<T>): Promise<T> {
  return auditCommitGate.run(() => withRuntimeFence(operation), Date.now() + AUDIT_COMMIT_WAIT_MS);
}

export function auditCommitSnapshot() {
  return auditCommitGate.snapshot();
}

async function assertAuditCommitAdmission(): Promise<void> {
  try {
    await checkpointQueue;
  } catch {
    // The stable failure object below is the authoritative admission result.
  }
  if (checkpointFailure) throw new AuditUnavailableError({ cause: checkpointFailure });
  if (checkpointIntegrityFailure) throw new AuditUnavailableError({ cause: checkpointIntegrityFailure });
  await assertExternalWitness();
}

async function appendAuditRow(
  store: any,
  entry: AuditEntry,
  allowCheckpointInitialization = false,
): Promise<CommittedAuditEntry> {
  // Serializes the chain across concurrent requests and future app processes.
  await store.execute(sql`select pg_advisory_xact_lock(1095520321)`);
  const previousRows = await store.select()
    .from(auditLogs)
    .orderBy(desc(auditLogs.createdAt), desc(auditLogs.id))
    .limit(1)
    .for('share') as Array<typeof auditLogs.$inferSelect>;
  const previous = previousRows[0] ?? null;
  await assertCheckpointDescendant(store, previous, allowCheckpointInitialization);
  const now = Date.now();
  // UUIDs are random, so two rows sharing a millisecond cannot be ordered by
  // (createdAt, id) in insertion order. The global chain lock lets us advance
  // the timestamp monotonically and makes verification deterministic.
  const createdAt = new Date(previous && previous.createdAt.getTime() >= now
    ? previous.createdAt.getTime() + 1
    : now);
  // Every row records an explicit outcome. Mutating helpers append only after
  // the state transaction succeeds; standalone `*.failed` security events are
  // the corresponding failure case.
  const context = currentLogContext();
  const details = {
    ...entry.details,
    ...(context ? {
      // requestId is generated by this server. traceId may originate at a
      // trusted upstream, but is strict-shape validated before correlation.
      requestId: context.requestId,
      traceId: context.traceId,
      ...(context.tenantId ? { tenantId: context.tenantId } : {}),
    } : {}),
    // Callers may add context, but cannot mislabel the outcome that is derived
    // from the audited action and transaction boundary.
    result: entry.action.endsWith('.failed') ? 'failure' : 'success',
  };
  const data = auditData({
    actorId: entry.actorId || null,
    action: entry.action,
    targetType: entry.targetType || null,
    targetId: entry.targetId || null,
    details,
    createdAt,
  });

  const [created] = await store.insert(auditLogs).values({
    actorId: entry.actorId || null,
    action: entry.action,
    targetType: entry.targetType || null,
    targetId: entry.targetId || null,
    details,
    prevHash: previous?.hash ?? null,
    hash: computeHash(data, previous?.hash ?? null),
    createdAt,
  }).returning({ id: auditLogs.id, hash: auditLogs.hash, createdAt: auditLogs.createdAt });
  if (!created) throw new Error('Audit entry was not committed');
  return created;
}

function enqueueCheckpoint(entry: CommittedAuditEntry): Promise<void> {
  // Recover the queue after an I/O failure so a transient error does not
  // permanently prevent later checkpoints from advancing.
  const next = checkpointQueue
    .catch(() => undefined)
    .then(() => writeAuditCheckpoint(entry.id, entry.hash, entry.createdAt))
    .then(() => {
      checkpointFailure = null;
    })
    .catch((error: unknown) => {
      checkpointFailure = error instanceof Error ? error : new Error('Audit checkpoint update failed');
      throw checkpointFailure;
    });
  checkpointQueue = next;
  return next;
}

export async function checkAuditCheckpoint(): Promise<void> {
  await assertExternalWitness();
  for (;;) {
    const observed = checkpointQueue;
    try {
      await observed;
    } catch {
      // The stable, redacted readiness error is handled by the caller.
    }
    if (observed === checkpointQueue) break;
  }
  if (checkpointFailure) throw checkpointFailure;
  if (checkpointIntegrityFailure) throw checkpointIntegrityFailure;
  let checkpoint: AuditCheckpoint | null;
  try {
    checkpoint = await readAuditCheckpoint();
  } catch (error) {
    throw latchCheckpointIntegrityFailure(error);
  }
  if (config.audit.checkpointRequired && !checkpoint) {
    throw latchCheckpointIntegrityFailure(new AuditCheckpointIntegrityError('Required audit checkpoint is not provisioned'));
  }
  if (checkpoint) {
    try {
      await db.transaction(async (transaction) => {
        await transaction.execute(sql`select pg_advisory_xact_lock(1095520321)`);
        await loadCheckpointAnchor(transaction, checkpoint);
      });
    } catch (error) {
      throw latchCheckpointIntegrityFailure(error);
    }
  }
}

export async function flushAuditCheckpoint(): Promise<void> {
  await checkAuditCheckpoint();
}

export async function verifyAuditChain(): Promise<{
  valid: boolean;
  checked: number;
  checkpoint: 'disabled' | 'initialized' | 'verified';
}> {
  const result = await verifyAuditChainNow();
  lastFullVerification = { valid: result.valid, checkpoint: result.checkpoint };
  return result;
}

async function verifyAuditChainNow(): Promise<{
  valid: boolean;
  checked: number;
  checkpoint: 'disabled' | 'initialized' | 'verified';
}> {
  await checkAuditCheckpoint();
  const checkpoint = config.audit.checkpointPath ? await readAuditCheckpoint() : null;
  const scan = await scanAuditRows(checkpoint);
  if (!scan.valid) return { valid: false, checked: scan.checked, checkpoint: checkpointMode() };
  const { checked, latest, checkpointMatched } = scan;

  if (!config.audit.checkpointPath) {
    if (config.audit.checkpointRequired) {
      return { valid: false, checked, checkpoint: 'disabled' };
    }
    return { valid: true, checked, checkpoint: 'disabled' };
  }

  if (checkpoint) {
    if (!checkpointMatched) return { valid: false, checked, checkpoint: 'verified' };
    if (checkpoint.version === 2) lastAcceptedCheckpoint = checkpoint;
    if (latest && (latest.id !== checkpoint.logId || checkpoint.version === 1)) {
      await writeAuditCheckpoint(latest.id, latest.hash, latest.createdAt);
    }
    return { valid: true, checked, checkpoint: 'verified' };
  }

  if (config.audit.checkpointRequired) {
    return { valid: false, checked, checkpoint: 'initialized' };
  }
  if (latest) await writeAuditCheckpoint(latest.id, latest.hash, latest.createdAt);
  return { valid: true, checked, checkpoint: 'initialized' };
}

/**
 * Cheap tenant-safe status for request paths. Full-chain verification remains
 * an operator/startup operation and cannot be triggered by workspace users.
 */
export async function getAuditIntegrityStatus(): Promise<{
  valid: boolean;
}> {
  try {
    await checkAuditCheckpoint();
    return { valid: lastFullVerification?.valid === true };
  } catch {
    return { valid: false };
  }
}

/** Explicit one-time operator action for a required checkpoint. */
export async function provisionAuditCheckpoint(): Promise<void> {
  if (!config.audit.checkpointPath) throw new Error('AUDIT_CHECKPOINT_PATH is required');
  if (await readAuditCheckpoint()) throw new Error('Audit checkpoint is already provisioned');
  // This command is the sole recovery/initialization boundary allowed to
  // replace a missing witness after independently validating the full chain.
  // Normal request/readiness paths can only set, never clear, the sticky latch.
  checkpointIntegrityFailure = null;
  try {
    const scan = await scanAuditRows(null);
    if (!scan.valid) throw new AuditCheckpointIntegrityError('Audit log integrity verification failed');
    if (scan.latest) {
      await writeAuditCheckpoint(scan.latest.id, scan.latest.hash, scan.latest.createdAt, true);
    } else {
      const initialized = await db.transaction((transaction) => appendAuditRow(transaction, {
        action: 'audit.checkpoint.provision',
        targetType: 'system',
        details: { operatorInitiated: true },
      }, true));
      await writeAuditCheckpoint(initialized.id, initialized.hash, initialized.createdAt, true);
    }
    checkpointFailure = null;
  } catch (error) {
    throw latchCheckpointIntegrityFailure(error);
  }
  const verified = await verifyAuditChain();
  if (!verified.valid) throw new Error('Provisioned audit checkpoint did not verify');
}

async function scanAuditRows(checkpoint: AuditCheckpoint | null): Promise<{
  valid: boolean;
  checked: number;
  latest: (typeof auditLogs.$inferSelect) | null;
  checkpointMatched: boolean;
}> {
  const witness = await loadExternalWitness();
  return db.transaction(async (transaction) => {
    let witnessMatched = !witness;
    let previous: string | null = null;
    let checked = 0;
    let cursor: { id: string; createdAt: Date } | null = null;
    let latest: (typeof auditLogs.$inferSelect) | null = null;
    let checkpointMatched = false;

    // Do not materialize an unbounded audit history. A repeatable-read snapshot
    // keeps all batches on one immutable view while hashes carry across them.
    for (;;) {
      const currentCursor = cursor;
      const rows: Array<typeof auditLogs.$inferSelect> = currentCursor
        ? await transaction.select()
          .from(auditLogs)
          .where(or(
            gt(auditLogs.createdAt, currentCursor.createdAt),
            and(eq(auditLogs.createdAt, currentCursor.createdAt), gt(auditLogs.id, currentCursor.id)),
          ))
          .orderBy(asc(auditLogs.createdAt), asc(auditLogs.id))
          .limit(1_000)
        : await transaction.select()
          .from(auditLogs)
          .orderBy(asc(auditLogs.createdAt), asc(auditLogs.id))
          .limit(1_000);
      if (rows.length === 0) break;

      for (const row of rows) {
        if (witness && row.id === witness.logId && row.hash === witness.logHash
          && row.createdAt.toISOString() === witness.logCreatedAt) witnessMatched = true;
        if (row.prevHash !== previous) return { valid: false, checked, latest, checkpointMatched };
        const expected = computeHash(auditData({
          actorId: row.actorId,
          action: row.action,
          targetType: row.targetType,
          targetId: row.targetId,
          details: row.details,
          createdAt: row.createdAt,
        }), previous);
        const actualBuffer = Buffer.from(row.hash, 'hex');
        const expectedBuffer = Buffer.from(expected, 'hex');
        if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) {
          return { valid: false, checked, latest, checkpointMatched };
        }
        if (checkpoint && row.id === checkpoint.logId) {
          if (
            !safeEqualHex(row.hash, checkpoint.logHash)
            || (checkpoint.version === 2 && row.createdAt.toISOString() !== checkpoint.logCreatedAt)
          ) {
            return { valid: false, checked, latest, checkpointMatched };
          }
          checkpointMatched = true;
        }
        previous = row.hash;
        latest = row;
        checked += 1;
      }
      const tail: typeof auditLogs.$inferSelect = rows.at(-1)!;
      cursor = { id: tail.id, createdAt: tail.createdAt };
      if (rows.length < 1_000) break;
    }
    return { valid: witnessMatched, checked, latest, checkpointMatched };
  }, { isolationLevel: 'repeatable read', accessMode: 'read only' });
}

function latchCheckpointIntegrityFailure(error: unknown): Error {
  if (error instanceof AuditCheckpointIntegrityError) {
    checkpointIntegrityFailure ??= error;
    return checkpointIntegrityFailure;
  }
  return error instanceof Error
    ? error
    : new Error('Audit checkpoint operation failed');
}

async function loadCheckpointAnchor(
  store: any,
  checkpoint: AuditCheckpoint,
): Promise<typeof auditLogs.$inferSelect> {
  const rows = await store.select()
    .from(auditLogs)
    .where(eq(auditLogs.id, checkpoint.logId))
    .limit(1)
    .for('share') as Array<typeof auditLogs.$inferSelect>;
  const anchor = rows[0];
  if (
    !anchor
    || !safeEqualHex(anchor.hash, checkpoint.logHash)
    || (checkpoint.version === 2 && anchor.createdAt.toISOString() !== checkpoint.logCreatedAt)
  ) {
    throw new AuditCheckpointIntegrityError('Audit checkpoint is not present in the database chain');
  }
  const expectedAnchorHash = computeHash(auditData({
    actorId: anchor.actorId,
    action: anchor.action,
    targetType: anchor.targetType,
    targetId: anchor.targetId,
    details: anchor.details,
    createdAt: anchor.createdAt,
  }), anchor.prevHash);
  if (!safeEqualHex(anchor.hash, expectedAnchorHash)) {
    throw new AuditCheckpointIntegrityError('Audit checkpoint row authentication failed');
  }
  if (checkpoint.version === 2) lastAcceptedCheckpoint = checkpoint;
  return anchor;
}

/**
 * Prove that a database row is a continuous HMAC-chain descendant of the
 * authenticated external checkpoint. The selected rows stay share-locked
 * until the caller's transaction ends, preventing a normal DB role from
 * deleting the witnessed chain between validation and commit/checkpoint CAS.
 */
async function assertCheckpointDescendant(
  store: any,
  descendant: CommittedAuditEntry | typeof auditLogs.$inferSelect | null,
  allowCheckpointInitialization = false,
  suppliedCheckpoint?: AuditCheckpoint | null,
): Promise<void> {
  if (!config.audit.checkpointPath) throw new AuditCheckpointIntegrityError('Audit checkpoint is not configured');
  if (checkpointIntegrityFailure && !allowCheckpointInitialization) throw checkpointIntegrityFailure;
  try {
    const checkpoint = suppliedCheckpoint === undefined
      ? await readAuditCheckpoint()
      : suppliedCheckpoint;
    if (!checkpoint) {
      if (!allowCheckpointInitialization && (config.audit.checkpointRequired || lastAcceptedCheckpoint)) {
        throw new AuditCheckpointIntegrityError('Required audit checkpoint is missing');
      }
      if (!descendant) return;
    } else if (!descendant) {
      throw new AuditCheckpointIntegrityError('Audit checkpoint is ahead of the database chain');
    }

    let cursor: { id: string; createdAt: Date } | null = null;
    let previousHash: string | null = null;
    if (checkpoint) {
      const anchor = await loadCheckpointAnchor(store, checkpoint);
      if (anchor.id === descendant!.id) {
        if (
          !safeEqualHex(anchor.hash, descendant!.hash)
          || anchor.createdAt.getTime() !== descendant!.createdAt.getTime()
        ) throw new AuditCheckpointIntegrityError('Audit checkpoint descendant does not match the database row');
        return;
      }
      cursor = { id: anchor.id, createdAt: anchor.createdAt };
      previousHash = anchor.hash;
    }

    for (;;) {
      const currentCursor = cursor;
      const rows: Array<typeof auditLogs.$inferSelect> = currentCursor
        ? await store.select()
          .from(auditLogs)
          .where(or(
            gt(auditLogs.createdAt, currentCursor.createdAt),
            and(eq(auditLogs.createdAt, currentCursor.createdAt), gt(auditLogs.id, currentCursor.id)),
          ))
          .orderBy(asc(auditLogs.createdAt), asc(auditLogs.id))
          .limit(1_000)
          .for('share') as Array<typeof auditLogs.$inferSelect>
        : await store.select()
          .from(auditLogs)
          .orderBy(asc(auditLogs.createdAt), asc(auditLogs.id))
          .limit(1_000)
          .for('share') as Array<typeof auditLogs.$inferSelect>;
      if (rows.length === 0) break;

      for (const row of rows) {
        const expected = computeHash(auditData({
          actorId: row.actorId,
          action: row.action,
          targetType: row.targetType,
          targetId: row.targetId,
          details: row.details,
          createdAt: row.createdAt,
        }), previousHash);
        if (row.prevHash !== previousHash || !safeEqualHex(row.hash, expected)) {
          throw new AuditCheckpointIntegrityError('Audit database chain no longer descends from the checkpoint');
        }
        if (row.id === descendant!.id) {
          if (
            !safeEqualHex(row.hash, descendant!.hash)
            || row.createdAt.getTime() !== descendant!.createdAt.getTime()
          ) throw new AuditCheckpointIntegrityError('Audit checkpoint descendant does not match the database row');
          return;
        }
        previousHash = row.hash;
        cursor = { id: row.id, createdAt: row.createdAt };
      }
      if (rows.length < 1_000) break;
    }
    throw new AuditCheckpointIntegrityError('Audit row is not a descendant of the external checkpoint');
  } catch (error) {
    throw latchCheckpointIntegrityFailure(error);
  }
}

function checkpointMode(): 'disabled' | 'initialized' | 'verified' {
  return config.audit.checkpointPath ? 'verified' : 'disabled';
}

function checkpointSignature(checkpoint: {
  version: 1 | 2;
  logId: string;
  logHash: string;
  logCreatedAt?: string;
  updatedAt: string;
}): string {
  return createHmac('sha256', config.audit.integrityKey)
    .update('alparts-audit-checkpoint-v1\0', 'utf8')
    .update(canonicalJson(checkpoint), 'utf8')
    .digest('hex');
}

async function readAuditCheckpoint(): Promise<AuditCheckpoint | null> {
  const path = config.audit.checkpointPath;
  if (!path) return null;
  let metadata;
  try {
    metadata = await stat(path);
  } catch (error: any) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!metadata.isFile() || metadata.size > 16 * 1024) {
    throw new AuditCheckpointIntegrityError('Invalid audit checkpoint file');
  }
  let parsed: unknown;
  const serialized = await readFile(path, 'utf8');
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new AuditCheckpointIntegrityError('Invalid audit checkpoint file');
  }
  if (!isAuditCheckpoint(parsed)) throw new AuditCheckpointIntegrityError('Invalid audit checkpoint file');
  const { signature, ...unsigned } = parsed;
  if (!safeEqualHex(signature, checkpointSignature(unsigned))) {
    throw new AuditCheckpointIntegrityError('Invalid audit checkpoint signature');
  }
  if (lastAcceptedCheckpoint) {
    if (parsed.version !== 2) throw new AuditCheckpointIntegrityError('Audit checkpoint rollback detected');
    const previousTime = Date.parse(lastAcceptedCheckpoint.logCreatedAt);
    const currentTime = Date.parse(parsed.logCreatedAt);
    if (
      currentTime < previousTime
      || (currentTime === previousTime && (
        parsed.logId !== lastAcceptedCheckpoint.logId
        || !safeEqualHex(parsed.logHash, lastAcceptedCheckpoint.logHash)
      ))
    ) throw new AuditCheckpointIntegrityError('Audit checkpoint rollback detected');
  }
  return parsed;
}

async function writeAuditCheckpoint(
  logId: string,
  logHash: string,
  logCreatedAt: Date,
  allowInitialization = false,
): Promise<void> {
  const path = config.audit.checkpointPath;
  if (!path) return;
  try {
    await db.transaction(async (transaction) => {
      // Hold the same database lock used by appenders while validating and
      // atomically replacing the external witness. This makes checkpoint
      // advancement a chain CAS instead of a timestamp-only overwrite.
      await transaction.execute(sql`select pg_advisory_xact_lock(1095520321)`);
      const current = await readAuditCheckpoint();
      if (!current && !allowInitialization && (config.audit.checkpointRequired || lastAcceptedCheckpoint)) {
        throw new AuditCheckpointIntegrityError('Required audit checkpoint is missing');
      }
      const currentAnchor = current ? await loadCheckpointAnchor(transaction, current) : null;
      if (current?.version === 2) {
        const currentTime = Date.parse(current.logCreatedAt);
        if (currentTime > logCreatedAt.getTime()) return;
        if (currentTime === logCreatedAt.getTime()) {
          if (current.logId !== logId || !safeEqualHex(current.logHash, logHash)) {
            throw new AuditCheckpointIntegrityError('Audit checkpoint conflicts with the committed audit row');
          }
          return;
        }
      } else if (current?.version === 1 && currentAnchor) {
        const currentTime = currentAnchor.createdAt.getTime();
        if (currentTime > logCreatedAt.getTime()) return;
        if (currentTime === logCreatedAt.getTime()) {
          if (current.logId !== logId || !safeEqualHex(current.logHash, logHash)) {
            throw new AuditCheckpointIntegrityError('Audit checkpoint conflicts with the committed audit row');
          }
          return;
        }
      }

      const descendant = { id: logId, hash: logHash, createdAt: logCreatedAt };
      await assertCheckpointDescendant(transaction, descendant, allowInitialization, current);

      const unsigned: Omit<AuditCheckpointV2, 'signature'> = {
        version: 2,
        logId,
        logHash,
        logCreatedAt: logCreatedAt.toISOString(),
        updatedAt: new Date().toISOString(),
      };
      const checkpoint: AuditCheckpoint = { ...unsigned, signature: checkpointSignature(unsigned) };
      const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
      let handle;
      try {
        handle = await open(temporary, 'wx', 0o600);
        await handle.writeFile(`${JSON.stringify(checkpoint)}\n`, 'utf8');
        await handle.sync();
        await handle.close();
        handle = undefined;
        await rename(temporary, path);
        const directory = await open(dirname(path), 'r');
        try {
          await directory.sync();
        } finally {
          await directory.close();
        }
        lastAcceptedCheckpoint = checkpoint as AuditCheckpointV2;
      } catch (error) {
        await handle?.close().catch(() => undefined);
        await unlink(temporary).catch(() => undefined);
        throw error;
      }
    });
  } catch (error) {
    throw latchCheckpointIntegrityFailure(error);
  }
}

function isAuditCheckpoint(value: unknown): value is AuditCheckpoint {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const common = typeof candidate.logId === 'string'
    && typeof candidate.logHash === 'string'
    && /^[a-f0-9]{64}$/.test(candidate.logHash)
    && typeof candidate.updatedAt === 'string'
    && Number.isFinite(Date.parse(candidate.updatedAt))
    && typeof candidate.signature === 'string'
    && /^[a-f0-9]{64}$/.test(candidate.signature);
  if (!common) return false;
  if (candidate.version === 1) return Object.keys(candidate).length === 5;
  return candidate.version === 2
    && Object.keys(candidate).length === 6
    && typeof candidate.logCreatedAt === 'string'
    && Number.isFinite(Date.parse(candidate.logCreatedAt));
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
