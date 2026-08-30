import { monitorEventLoopDelay } from 'node:perf_hooks';
import { dbPoolSnapshot } from '../db/index.js';
import { auditCommitSnapshot } from '../middleware/audit.js';
import { passwordWorkSnapshot } from '../security/password-work.js';
import { objectStorageWorkSnapshot } from '../services/object-storage.js';

const requestCounts = new Map<string, number>();
const durationBucketsMs = [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];
const durationCounts = Array.from({ length: durationBucketsMs.length }, () => 0);
let durationCount = 0;
let durationSumMs = 0;
const eventLoop = monitorEventLoopDelay({ resolution: 20 });
eventLoop.enable();

export function observeHttpRequest(method: string, status: number, durationMs: number): void {
  const safeMethod = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].includes(method) ? method : 'OTHER';
  const statusClass = status >= 500 ? '5xx' : status >= 400 ? '4xx' : status >= 300 ? '3xx' : status >= 200 ? '2xx' : 'other';
  const key = `${safeMethod}:${statusClass}`;
  requestCounts.set(key, (requestCounts.get(key) ?? 0) + 1);
  durationCount += 1;
  durationSumMs += durationMs;
  for (let index = 0; index < durationBucketsMs.length; index += 1) {
    if (durationMs <= durationBucketsMs[index]) durationCounts[index] += 1;
  }
}

export function renderPrometheusMetrics(): string {
  const lines: string[] = [
    '# HELP alparts_http_requests_total Completed HTTP requests.',
    '# TYPE alparts_http_requests_total counter',
  ];
  for (const [key, value] of [...requestCounts.entries()].sort()) {
    const [method, statusClass] = key.split(':');
    lines.push(`alparts_http_requests_total{method="${method}",status_class="${statusClass}"} ${value}`);
  }
  lines.push(
    '# HELP alparts_http_request_duration_milliseconds HTTP request duration.',
    '# TYPE alparts_http_request_duration_milliseconds histogram',
  );
  durationBucketsMs.forEach((upper, index) => {
    lines.push(`alparts_http_request_duration_milliseconds_bucket{le="${upper}"} ${durationCounts[index]}`);
  });
  lines.push(`alparts_http_request_duration_milliseconds_bucket{le="+Inf"} ${durationCount}`);
  lines.push(`alparts_http_request_duration_milliseconds_sum ${durationSumMs}`);
  lines.push(`alparts_http_request_duration_milliseconds_count ${durationCount}`);

  const db = dbPoolSnapshot();
  const audit = auditCommitSnapshot();
  const password = passwordWorkSnapshot();
  const objectStorage = objectStorageWorkSnapshot();
  const memory = process.memoryUsage();
  gauge(lines, 'alparts_db_pool_connections', 'PostgreSQL pool connections by state.', {
    total: db.total,
    idle: db.idle,
    waiting: db.waiting,
    max: db.max,
  });
  gauge(lines, 'alparts_password_work', 'Password-work bulkhead utilization.', {
    active: password.active,
    pending: password.pending,
    concurrency: password.concurrency,
    max_pending: password.maxPending,
  });
  gauge(lines, 'alparts_audit_commit_work', 'Authoritative audit-admission bulkhead utilization.', {
    active: audit.active,
    pending: audit.pending,
    concurrency: audit.concurrency,
    max_pending: audit.maxPending,
  });
  gauge(lines, 'alparts_object_storage_work', 'Object-storage bulkhead utilization.', {
    active: objectStorage.active,
    pending: objectStorage.pending,
    concurrency: objectStorage.concurrency,
    max_pending: objectStorage.maxPending,
  });
  lines.push('# HELP alparts_process_memory_bytes Node.js process memory usage.');
  lines.push('# TYPE alparts_process_memory_bytes gauge');
  lines.push(`alparts_process_memory_bytes{kind="rss"} ${memory.rss}`);
  lines.push(`alparts_process_memory_bytes{kind="heap_used"} ${memory.heapUsed}`);
  lines.push(`alparts_process_memory_bytes{kind="external"} ${memory.external}`);
  lines.push('# HELP alparts_event_loop_delay_seconds Event-loop delay observed by Node.js.');
  lines.push('# TYPE alparts_event_loop_delay_seconds gauge');
  lines.push(`alparts_event_loop_delay_seconds{quantile="0.50"} ${finiteSeconds(eventLoop.percentile(50))}`);
  lines.push(`alparts_event_loop_delay_seconds{quantile="0.99"} ${finiteSeconds(eventLoop.percentile(99))}`);
  lines.push(`alparts_event_loop_delay_seconds{quantile="max"} ${finiteSeconds(eventLoop.max)}`);
  lines.push('# HELP alparts_process_uptime_seconds Process uptime.');
  lines.push('# TYPE alparts_process_uptime_seconds gauge');
  lines.push(`alparts_process_uptime_seconds ${process.uptime()}`);
  return `${lines.join('\n')}\n`;
}

function gauge(lines: string[], name: string, help: string, values: Record<string, number>): void {
  lines.push(`# HELP ${name} ${help}`);
  lines.push(`# TYPE ${name} gauge`);
  for (const [state, value] of Object.entries(values)) lines.push(`${name}{state="${state}"} ${value}`);
}

function finiteSeconds(nanoseconds: number): number {
  return Number.isFinite(nanoseconds) ? nanoseconds / 1_000_000_000 : 0;
}
