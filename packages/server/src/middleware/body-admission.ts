import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { presentedSessionUser, type AuthRequest } from './auth.js';
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

/** The ordinary limit on a JSON body, and the most a request without a usable session may send. */
export const DEFAULT_JSON_BODY_BYTES = 512 * 1024;
// Counted per user from the signed token, so one account cannot widen its share
// by changing address.
const jsonBodyBudget = new InFlightBodyBudget({
  maxBytesTotal: 8 * MiB,
  maxBytesPerUser: 2 * MiB,
  maxRequestsTotal: 32,
  maxRequestsPerUser: 8,
});
// Sign-in, registration and anything else without a usable session is counted
// per source address in a smaller budget of its own, so it cannot use up the
// capacity signed-in users need.
const anonymousJsonBodyBudget = new InFlightBodyBudget({
  maxBytesTotal: 2 * MiB,
  maxBytesPerUser: DEFAULT_JSON_BODY_BYTES,
  maxRequestsTotal: 16,
  maxRequestsPerUser: 4,
});

const BODY_START_MS = 10_000;
const BODY_MIN_BYTES_PER_SECOND = 32 * 1024;

/**
 * How long a body of this declared size may take to arrive: a short start plus
 * the time the size needs at a modest minimum rate. A client that stalls holds
 * its reservation no longer than this.
 */
export function bodyDeadlineMs(bytes: number): number {
  return BODY_START_MS + Math.ceil((bytes / BODY_MIN_BYTES_PER_SECOND) * 1000);
}

/** Answer a body that did not arrive in time, and give its reservation back at once. */
function abortStalledBody(req: Request, res: Response, release: () => void): void {
  release();
  if (res.headersSent) {
    req.destroy();
    return;
  }
  res.setHeader('Connection', 'close');
  res.status(408).json({ error: 'REQUEST_TIMEOUT', message: 'Request body was not received in time', statusCode: 408 });
}

/**
 * Bound aggregate JSON allocation before Express starts buffering/parsing.
 * `maxBytes` is the allowance of a request that presents a usable session;
 * everyone else gets the ordinary limit. A body not fully received within its
 * deadline is refused with 408 and its reservation is released.
 */
export function reserveJsonBody(
  maxBytes: number,
  deadlineMs: (bytes: number) => number = bodyDeadlineMs,
): RequestHandler {
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
    const userId = presentedSessionUser(req);
    const limit = userId ? maxBytes : Math.min(maxBytes, DEFAULT_JSON_BODY_BYTES);
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > limit) {
      res.status(413).json({ error: 'BODY_TOO_LARGE', message: 'JSON body is too large', statusCode: 413 });
      return;
    }
    const release = userId
      ? jsonBodyBudget.acquire(userId, bytes)
      : anonymousJsonBodyBudget.acquire(requestSource(req), bytes);
    if (!release) {
      res.status(503).json({ error: 'BODY_CAPACITY', message: 'Request body capacity is exhausted', statusCode: 503 });
      return;
    }
    const deadline = setTimeout(() => {
      if (!req.complete) abortStalledBody(req, res, release);
    }, deadlineMs(bytes));
    deadline.unref();
    const finished = () => {
      clearTimeout(deadline);
      release();
    };
    res.once('finish', finished);
    res.once('close', finished);
    req.once('aborted', finished);
    // The reservation stays until the request ends; only the wait for the body stops here.
    req.once('end', () => clearTimeout(deadline));
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
