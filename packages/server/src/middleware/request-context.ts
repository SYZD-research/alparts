import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import { logInfo } from '../security/logger.js';

/**
 * Give every HTTP exchange an untrusted-input-independent correlation ID.
 * Logs deliberately omit raw paths, query strings, IPs, cookies, and user IDs.
 */
export const requestContext: RequestHandler = (req, res, next) => {
  const requestId = randomUUID();
  const startedAt = process.hrtime.bigint();
  res.locals.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  res.once('finish', () => {
    const elapsed = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
    logInfo('http.request', {
      requestId,
      method: req.method,
      status: res.statusCode,
      durationMs: Math.round(elapsed * 10) / 10,
    });
  });
  next();
};
