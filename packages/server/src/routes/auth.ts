import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import * as authService from '../services/auth.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import {
  credentialAccountRateLimitKey,
  credentialRateLimitKey,
  rateLimit,
} from '../middleware/rate-limit.js';
import { config } from '../config/index.js';
import { expiredSessionCookie, sessionCookie } from '../security/cookies.js';

const router = Router();
const password = z.string().min(12).max(72).refine((value) => Buffer.byteLength(value, 'utf8') <= 72);
const loginPassword = z.string().min(1).max(72).refine((value) => Buffer.byteLength(value, 'utf8') <= 72);
const registerSchema = z.object({
  email: z.string().email().max(254),
  password,
  displayName: z.string().trim().min(1).max(100),
  inviteToken: z.string().min(1).max(512),
}).strict();
const loginSchema = z.object({
  email: z.string().email().max(254),
  // bcrypt ignores bytes after 72; reject them so an appended suffix can
  // never authenticate as the same password.
  password: loginPassword,
  deviceInfo: z.object({
    platform: z.string().max(80).optional(),
    browser: z.string().max(200).optional(),
    language: z.string().max(32).optional(),
  }).strict().optional(),
}).strict();

const registrationLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, key: credentialRateLimitKey });
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, key: credentialRateLimitKey });
const loginAccountLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 12, key: credentialAccountRateLimitKey });
const registrationIpLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 30 });
const loginIpLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const sessionIdSchema = z.string().uuid();

router.post('/register', registrationIpLimit, registrationLimit, async (req, res) => {
  try {
    const body = registerSchema.parse(req.body);
    const user = await authService.register(body.email, body.password, body.displayName, body.inviteToken);
    res.status(201).json(user);
  } catch (error: any) {
    if (error.message === 'INVALID_INVITATION' || error.message === 'EMAIL_EXISTS') {
      res.status(403).json({ error: 'INVITE_REQUIRED', message: 'A valid invitation is required', statusCode: 403 });
      return;
    }
    if (error.name === 'ZodError' || error.message === 'INVALID_PASSWORD_LENGTH') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid registration data', statusCode: 400 });
      return;
    }
    if (error.message === 'WORKSPACE_MEMBER_LIMIT') {
      res.status(409).json({ error: 'WORKSPACE_MEMBER_LIMIT', message: 'Workspace member limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.post('/login', loginIpLimit, loginAccountLimit, loginLimit, async (req, res) => {
  try {
    const body = loginSchema.parse(req.body);
    const result = await authService.login(body.email, body.password, body.deviceInfo);
    res.setHeader('Set-Cookie', sessionCookie(result.token, config.jwt.expiresInSeconds));
    res.setHeader('Cache-Control', 'no-store');
    res.json({ user: result.user });
  } catch (error: any) {
    if (error.message === 'INVALID_CREDENTIALS') {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid email or password', statusCode: 401 });
      return;
    }
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid login data', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.post('/logout', authMiddleware, async (req: AuthRequest, res) => {
  await authService.logout(req.sessionId!, req.userId!);
  const io = req.app.get('io') as SocketServer | undefined;
  io?.in(`session:${req.sessionId}`).disconnectSockets(true);
  res.setHeader('Set-Cookie', expiredSessionCookie());
  res.setHeader('Cache-Control', 'no-store');
  res.json({ success: true });
});

router.get('/me', authMiddleware, async (req: AuthRequest, res) => {
  const user = await authService.getUserById(req.userId!);
  if (!user) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'User not found', statusCode: 404 });
    return;
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json(user);
});

router.get('/sessions', authMiddleware, async (req: AuthRequest, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(await authService.listSessions(req.userId!, req.sessionId!));
});

router.delete('/sessions/:id', authMiddleware, async (req: AuthRequest, res) => {
  if (!sessionIdSchema.safeParse(req.params.id).success || !await authService.revokeSession(req.userId!, req.params.id)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Session not found', statusCode: 404 });
    return;
  }
  const io = req.app.get('io') as SocketServer | undefined;
  io?.in(`session:${req.params.id}`).disconnectSockets(true);
  if (req.params.id === req.sessionId) res.setHeader('Set-Cookie', expiredSessionCookie());
  res.json({ success: true });
});

router.delete('/sessions', authMiddleware, async (req: AuthRequest, res) => {
  const sessionIds = await authService.revokeAllSessions(req.userId!);
  const io = req.app.get('io') as SocketServer | undefined;
  for (const sessionId of sessionIds) io?.in(`session:${sessionId}`).disconnectSockets(true);
  res.setHeader('Set-Cookie', expiredSessionCookie());
  res.json({ success: true, revoked: sessionIds.length });
});

export default router;
