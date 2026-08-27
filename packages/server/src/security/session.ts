import { createHash } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { and, eq, gt, isNull } from 'drizzle-orm';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { sessions } from '../db/schema.js';

export interface ActiveSession {
  userId: string;
  sessionId: string;
  deviceId: string | null;
  tokenHash: string;
  expiresAtMs: number;
}

export function hashSessionToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export async function verifySessionToken(token: string): Promise<ActiveSession | null> {
  if (token.length > 4096) return null;

  let payload: jwt.JwtPayload;
  try {
    const verified = jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'],
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });
    if (typeof verified === 'string') return null;
    payload = verified;
  } catch {
    return null;
  }

  const userId = payload.sub;
  const sessionId = payload.sid;
  if (typeof userId !== 'string' || typeof sessionId !== 'string' || typeof payload.exp !== 'number') return null;

  const tokenHash = hashSessionToken(token);
  const session = await db.query.sessions.findFirst({
    where: and(
      eq(sessions.id, sessionId),
      eq(sessions.userId, userId),
      eq(sessions.tokenHash, tokenHash),
      gt(sessions.expiresAt, new Date()),
    ),
  });
  if (!session) return null;

  const expiresAtMs = Math.min(payload.exp * 1000, session.expiresAt.getTime());
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) return null;
  return { userId, sessionId, deviceId: session.deviceId, tokenHash, expiresAtMs };
}

export async function isSessionActive(
  session: Pick<ActiveSession, 'userId' | 'sessionId' | 'deviceId' | 'tokenHash'>,
): Promise<boolean> {
  const row = await db.query.sessions.findFirst({
    columns: { id: true },
    where: and(
      eq(sessions.id, session.sessionId),
      eq(sessions.userId, session.userId),
      eq(sessions.tokenHash, session.tokenHash),
      session.deviceId === null
        ? isNull(sessions.deviceId)
        : eq(sessions.deviceId, session.deviceId),
      gt(sessions.expiresAt, new Date()),
    ),
  });
  return Boolean(row);
}
