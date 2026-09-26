import type { NextFunction, Request, Response } from 'express';
import { config } from '../config/index.js';
import { readCookie } from '../security/cookies.js';
import { verifySessionToken } from '../security/session.js';
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
  try {
    if (!await authenticate(req)) {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
      return;
    }
    next();
  } catch {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
  }
}

export async function optionalAuth(req: AuthRequest, _res: Response, next: NextFunction) {
  try {
    await authenticate(req);
  } catch {
    // Optional authentication deliberately continues without an identity.
  }
  next();
}
