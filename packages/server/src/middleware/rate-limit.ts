import { createHash } from 'node:crypto';
import type { Request, RequestHandler } from 'express';

interface RateLimitOptions {
  windowMs: number;
  max: number;
  key?: (req: Request) => string;
}

interface Counter { count: number; resetAt: number }

export function rateLimit(options: RateLimitOptions): RequestHandler {
  const counters = new Map<string, Counter>();
  const maxEntries = 20_000;

  return (req, res, next) => {
    const now = Date.now();
    const key = options.key?.(req) || req.ip || req.socket.remoteAddress || 'unknown';
    let counter = counters.get(key);
    if (!counter || counter.resetAt <= now) {
      if (counters.size >= maxEntries) {
        for (const [candidate, value] of counters) {
          if (value.resetAt <= now) counters.delete(candidate);
          if (counters.size < maxEntries) break;
        }
      }
      if (counters.size >= maxEntries) {
        res.status(503).json({ error: 'RATE_LIMIT_CAPACITY', message: 'Try again later', statusCode: 503 });
        return;
      }
      counter = { count: 0, resetAt: now + options.windowMs };
      counters.set(key, counter);
    }

    counter.count += 1;
    res.setHeader('RateLimit-Limit', String(options.max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, options.max - counter.count)));
    res.setHeader('RateLimit-Reset', String(Math.ceil(counter.resetAt / 1000)));
    if (counter.count > options.max) {
      res.setHeader('Retry-After', String(Math.ceil((counter.resetAt - now) / 1000)));
      res.status(429).json({ error: 'RATE_LIMITED', message: 'Too many requests', statusCode: 429 });
      return;
    }
    next();
  };
}

export function credentialRateLimitKey(req: Request): string {
  const emailHash = credentialAccountRateLimitKey(req);
  return `${req.ip || req.socket.remoteAddress || 'unknown'}:${emailHash}`;
}

/**
 * Account-scoped credential budget. Keeping this independent from the source
 * address prevents a distributed password spray from resetting the budget by
 * rotating IPs, while hashing avoids retaining account identifiers in memory.
 */
export function credentialAccountRateLimitKey(req: Request): string {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  return createHash('sha256').update(email).digest('hex').slice(0, 24);
}
