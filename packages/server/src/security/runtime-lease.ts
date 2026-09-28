import pg from 'pg';
import { sql } from 'drizzle-orm';
import { config } from '../config/index.js';
import { db } from '../db/index.js';

const OWNER_LOCK = 1095520341;
const DRAIN_LOCK = 1095520342;
let current: RuntimeLease | undefined;

/** A dedicated, non-reconnecting PostgreSQL session enforces the supported
 * single-process topology. A second lock fences mutations through checkpoint
 * persistence, so a replacement waits for already-admitted work to finish. */
export class RuntimeLease {
  private valid = true;
  private listeners = new Set<() => void>();
  private disabledListeners = new Set<(userId: string) => void>();
  constructor(
    private client: pg.Client,
    private pid: number,
  ) {
    client.on('error', () => this.invalidate());
    client.on('end', () => this.invalidate());
    client.on('notification', (message) => {
      if (message.channel === 'alparts_account_disabled' && /^[0-9a-f-]{36}$/i.test(message.payload ?? '')) {
        for (const listener of this.disabledListeners) listener(message.payload!);
      }
    });
  }
  private invalidate() {
    if (!this.valid) return;
    this.valid = false;
    for (const listener of this.listeners) listener();
  }
  isAlive() {
    return this.valid;
  }
  onAccountDisabled(listener: (userId: string) => void) {
    this.disabledListeners.add(listener);
  }
  onLost(listener: () => void) {
    this.listeners.add(listener);
    if (!this.valid) listener();
  }
  async check(store: any = db): Promise<void> {
    if (!this.valid) throw new Error('RUNTIME_LEASE_LOST');
    try {
      const result = await store.execute(sql`select 1 from pg_locks
        where locktype = 'advisory' and pid = ${this.pid} and classid = 0
        and objid = ${OWNER_LOCK} and objsubid = 1 and granted
        and database = (select oid from pg_database where datname = current_database())`);
      if (!result.rows.length || !this.valid) throw new Error('RUNTIME_LEASE_LOST');
    } catch {
      this.invalidate();
      throw new Error('RUNTIME_LEASE_LOST');
    }
  }
  async fence<T>(operation: () => Promise<T>): Promise<T> {
    return db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock_shared(${DRAIN_LOCK})`);
      await this.check(tx);
      return operation();
    });
  }
  async close() {
    this.invalidate();
    await this.client.end();
  }
}

export async function acquireRuntimeLease(): Promise<RuntimeLease> {
  if (config.db.poolMax < 2) throw new Error('RUNTIME_REQUIRES_TWO_DATABASE_CONNECTIONS');
  const client = new pg.Client({
    connectionString: config.db.url,
    ssl: config.db.ssl ? { rejectUnauthorized: true } : undefined,
    connectionTimeoutMillis: config.db.connectTimeoutMs,
    query_timeout: config.db.statementTimeoutMs + 1_000,
    keepAlive: true,
    keepAliveInitialDelayMillis: 1000,
    application_name: 'alparts-runtime-lease',
  });
  // Attach before connecting; startup connection loss must also fail closed.
  let lost = false;
  client.on('error', () => {
    lost = true;
  });
  try {
    await client.connect();
    const result = await client.query<{ held: boolean; pid: number }>(
      'select pg_try_advisory_lock($1) as held, pg_backend_pid() as pid',
      [OWNER_LOCK],
    );
    if (!result.rows[0].held) throw new Error('RUNTIME_ALREADY_ACTIVE');
    await client.query('select pg_advisory_lock($1)', [DRAIN_LOCK]);
    await client.query('select pg_advisory_unlock($1)', [DRAIN_LOCK]);
    if (lost) throw new Error('RUNTIME_LEASE_LOST');
    await client.query('LISTEN alparts_account_disabled');
    current = new RuntimeLease(client, result.rows[0].pid);
    return current;
  } catch (error) {
    await client.end().catch(() => undefined);
    throw error;
  }
}

export function requireRuntimeLease(): RuntimeLease {
  if (!current) throw new Error('RUNTIME_LEASE_REQUIRED');
  return current;
}

/** Offline operator tools serialize across the complete commit/checkpoint
 * window without acquiring the HTTP runtime's owner lock. */
export async function withOperatorMutation<T>(operation: () => Promise<T>): Promise<T> {
  const client = new pg.Client({
    connectionString: config.db.url,
    ssl: config.db.ssl ? { rejectUnauthorized: true } : undefined,
    connectionTimeoutMillis: config.db.connectTimeoutMs,
    query_timeout: config.db.statementTimeoutMs,
    application_name: 'alparts-operator-mutation',
  });
  let disconnected = false;
  client.on('error', () => { disconnected = true; });
  try {
    await client.connect();
    await client.query('select pg_advisory_lock($1)', [DRAIN_LOCK]);
    if (disconnected) throw new Error('OPERATOR_LOCK_LOST');
    return await operation();
  } finally { await client.end(); }
}

export function withRuntimeFence<T>(operation: () => Promise<T>): Promise<T> {
  // Offline migration/checkpoint provisioning has no HTTP listener. createApp
  // always requires the lease, and a lost lease never falls back to this path.
  return current ? current.fence(operation) : operation();
}
