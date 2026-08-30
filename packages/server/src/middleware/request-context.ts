import { randomBytes, randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import { logInfo } from '../security/logger.js';
import { runWithLogContext, type LogContext } from '../security/log-context.js';
import { observeHttpRequest } from '../observability/metrics.js';

/**
 * Give every HTTP exchange an untrusted-input-independent correlation ID.
 * Logs deliberately omit raw paths, query strings, IPs, cookies, and user IDs.
 */
export const requestContext: RequestHandler = (req, res, next) => {
  const requestId = randomUUID();
  const traceId = parseTraceId(req.headers.traceparent) ?? randomBytes(16).toString('hex');
  const spanId = randomBytes(8).toString('hex');
  const startedAt = process.hrtime.bigint();
  res.locals.requestId = requestId;
  res.locals.traceId = traceId;
  res.setHeader('X-Request-Id', requestId);
  res.setHeader('traceparent', `00-${traceId}-${spanId}-01`);
  const context: LogContext = { requestId, traceId };
  runWithLogContext(context, () => {
    res.once('finish', () => {
      const elapsed = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      observeHttpRequest(req.method, res.statusCode, elapsed);
      logInfo('http.request', {
        requestId,
        traceId,
        method: req.method,
        status: res.statusCode,
        durationMs: Math.round(elapsed * 10) / 10,
        outcome: res.statusCode < 400 ? 'success' : res.statusCode < 500 ? 'client_error' : 'server_error',
        ...(context.tenantId ? { tenantId: context.tenantId } : {}),
      });
    });
    next();
  });
};

function parseTraceId(value: string | string[] | undefined): string | null {
  if (typeof value !== 'string') return null;
  const match = /^00-([a-f0-9]{32})-[a-f0-9]{16}-[0-9a-f]{2}$/.exec(value.toLowerCase());
  return match && match[1] !== '00000000000000000000000000000000' ? match[1] : null;
}
