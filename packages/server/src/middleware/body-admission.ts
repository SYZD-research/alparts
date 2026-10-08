import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AuthRequest } from './auth.js';
import { requestSource } from './rate-limit.js';

interface BodyBudgetLimits {
  maxBytesTotal: number;
  maxBytesPerUser: number;
  maxRequestsTotal: number;
  maxRequestsPerUser: number;
}

export class InFlightBodyBudget {
  private totalBytes = 0;
  private totalRequests = 0;
  private readonly users = new Map<string, { bytes: number; requests: number }>();

  constructor(private readonly limits: BodyBudgetLimits) {}

  acquire(userId: string, bytes: number): (() => void) | null {
    if (!userId || !Number.isSafeInteger(bytes) || bytes < 0) return null;
    const user = this.users.get(userId) ?? { bytes: 0, requests: 0 };
    if (
      this.totalBytes + bytes > this.limits.maxBytesTotal
      || user.bytes + bytes > this.limits.maxBytesPerUser
      || this.totalRequests >= this.limits.maxRequestsTotal
      || user.requests >= this.limits.maxRequestsPerUser
    ) return null;
    this.totalBytes += bytes;
    this.totalRequests += 1;
    user.bytes += bytes;
    user.requests += 1;
    this.users.set(userId, user);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.totalBytes -= bytes;
      this.totalRequests -= 1;
      user.bytes -= bytes;
      user.requests -= 1;
      if (user.requests === 0) this.users.delete(userId);
    };
  }
}

const MiB = 1024 * 1024;
const attachmentBodyBudget = new InFlightBodyBudget({
  maxBytesTotal: 40 * MiB,
  maxBytesPerUser: 11 * MiB,
  maxRequestsTotal: 8,
  maxRequestsPerUser: 2,
});
const jsonBodyBudget = new InFlightBodyBudget({
  maxBytesTotal: 8 * MiB,
  maxBytesPerUser: 2 * MiB,
  maxRequestsTotal: 32,
  maxRequestsPerUser: 8,
});

/** Bound aggregate JSON allocation before Express starts buffering/parsing. */
export function reserveJsonBody(maxBytes: number): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD' || !req.is('application/json')) {
      next();
      return;
    }
    if (req.headers['transfer-encoding'] !== undefined) {
      res.status(400).json({ error: 'INVALID_BODY_LENGTH', message: 'Chunked JSON bodies are not accepted', statusCode: 400 });
      return;
    }
    const header = req.headers['content-length'];
    if (typeof header !== 'string' || !/^\d+$/.test(header)) {
      res.status(411).json({ error: 'LENGTH_REQUIRED', message: 'Content-Length is required', statusCode: 411 });
      return;
    }
    const bytes = Number(header);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxBytes) {
      res.status(413).json({ error: 'BODY_TOO_LARGE', message: 'JSON body is too large', statusCode: 413 });
      return;
    }
    const source = requestSource(req);
    const release = jsonBodyBudget.acquire(source, bytes);
    if (!release) {
      res.status(503).json({ error: 'BODY_CAPACITY', message: 'Request body capacity is exhausted', statusCode: 503 });
      return;
    }
    res.once('finish', release);
    res.once('close', release);
    req.once('aborted', release);
    next();
  };
}

export function reserveKnownLengthBody(maxBytes: number): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.headers['transfer-encoding'] !== undefined) {
      res.status(400).json({ error: 'INVALID_BODY_LENGTH', message: 'Chunked request bodies are not accepted', statusCode: 400 });
      return;
    }
    const header = req.headers['content-length'];
    if (typeof header !== 'string' || !/^\d+$/.test(header)) {
      res.status(411).json({ error: 'LENGTH_REQUIRED', message: 'Content-Length is required', statusCode: 411 });
      return;
    }
    const bytes = Number(header);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxBytes) {
      res.status(413).json({ error: 'CHUNK_TOO_LARGE', message: 'Attachment chunk is too large', statusCode: 413 });
      return;
    }
    const userId = (req as AuthRequest).userId;
    const release = userId ? attachmentBodyBudget.acquire(userId, bytes) : null;
    if (!release) {
      res.status(503).json({ error: 'BODY_CAPACITY', message: 'Upload capacity is currently exhausted', statusCode: 503 });
      return;
    }
    res.locals.expectedBodyBytes = bytes;
    res.once('finish', release);
    res.once('close', release);
    req.once('aborted', release);
    next();
  };
}

/**
 * The bytes left in `req.body` by an `express.raw` parser, or null when the
 * request produced none. CodeQL separates request strings from arrays only on a
 * `typeof` test, not on `Buffer.isBuffer`, so the test is spelled out here.
 */
export function rawRequestBody(req: Request): Buffer | null {
  const body: unknown = req.body;
  if (typeof body !== 'object' || !Buffer.isBuffer(body)) return null;
  return body;
}
