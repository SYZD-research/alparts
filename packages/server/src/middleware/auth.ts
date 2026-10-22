import type { NextFunction, Request, Response } from 'express';
import { config } from '../config/index.js';
import { readCookie } from '../security/cookies.js';
import { verifySessionClaims, verifySessionToken } from '../security/session.js';
import { updateLastActive } from '../services/device.service.js';
import { setLogActor } from '../security/log-context.js';

import type { StepUpProof } from '../services/passkey.service.js';

export interface AuthRequest extends Request {
  params: Record<string, string>;
  userId?: string;
  sessionId?: string;
  deviceId?: string | null;
  sessionTokenHash?: string;
  stepUpProof?: StepUpProof;
  authTransport?: 'cookie' | 'bearer';
}

function requestToken(req: Request): { token: string; transport: 'cookie' | 'bearer' } | null {
  const cookieToken = readCookie(req.headers.cookie, config.auth.cookieName);
  if (cookieToken) return { token: cookieToken, transport: 'cookie' };

  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ') && header.length <= 4103) {
    return { token: header.slice(7), transport: 'bearer' };
  }
  return null;
}

/**
 * The user named by the session token a request presents, when the token
 * passes the checks that need no database. That the session is still live is
 * not known here; use this only to decide how much to spend before the real
 * authentication runs.
 */
export function presentedSessionUser(req: Request): string | null {
  const candidate = requestToken(req);
  return candidate ? verifySessionClaims(candidate.token)?.userId ?? null : null;
}

async function authenticate(req: AuthRequest): Promise<boolean> {
  const candidate = requestToken(req);
  if (!candidate) return false;
  const session = await verifySessionToken(candidate.token);
  if (!session) return false;
  req.userId = session.userId;
  req.sessionId = session.sessionId;
  req.deviceId = session.deviceId;
  req.sessionTokenHash = session.tokenHash;
  req.authTransport = candidate.transport;
  setLogActor(session.userId);
  if (session.deviceId) void updateLastActive(session.deviceId).catch(() => undefined);
  return true;
}

export async function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  let authenticated: boolean;
  try {
    authenticated = await authenticate(req);
  } catch (error) {
    // A session that could not be looked up is not a missing one. A 401 would
    // tell a client that is signing out that its session has already ended.
    next(error);
    return;
  }
  if (!authenticated) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
    return;
  }
  next();
}

export async function optionalAuth(req: AuthRequest, _res: Response, next: NextFunction) {
  try {
    await authenticate(req);
  } catch {
    // Optional authentication deliberately continues without an identity.
  }
  next();
}
