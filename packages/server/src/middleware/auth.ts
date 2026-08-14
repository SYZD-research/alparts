import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { sessions, users } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';

export interface AuthRequest extends Request {
  userId?: string;
  sessionId?: string;
}

export function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing or invalid token', statusCode: 401 });
    return;
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, config.jwt.secret) as { userId: string; sessionId: string };
    req.userId = payload.userId;
    req.sessionId = payload.sessionId;
    next();
  } catch {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid or expired token', statusCode: 401 });
  }
}

export function optionalAuth(req: AuthRequest, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    next();
    return;
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, config.jwt.secret) as { userId: string; sessionId: string };
    req.userId = payload.userId;
    req.sessionId = payload.sessionId;
  } catch {
    // Ignore invalid token for optional auth
  }
  next();
}
