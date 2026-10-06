import { displayText } from '../security/display-text.js';
import { Router } from 'express';
import { isAccountSecurityError } from '../security/account-errors.js';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import * as deviceService from '../services/device.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { expiredSessionCookie } from '../security/cookies.js';
import { rateLimit, requestSource } from '../middleware/rate-limit.js';

const router = Router();
const registerSchema = z.object({
  name: displayText(),
  identityKey: z.string().min(1).max(16 * 1024),
  challenge: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  proof: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
  currentPassword: z.string().min(1).max(72)
    .refine((value) => Buffer.byteLength(value, 'utf8') <= 72)
    .optional(),
}).strict();
const proofSchema = z.object({
  challenge: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  proof: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
}).strict();
const decisionSchema = z.object({ head: z.object({ userId: z.string().uuid(), sequence: z.number().int().min(0).max(8192), hash: z.string().regex(/^[a-f0-9]{64}$/) }).strict(), signature: z.string().length(88) }).strict();
const idSchema = z.string().uuid();
const challengeLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const enrollmentLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const revocationLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});

router.post('/challenge', authMiddleware, challengeLimit, (req: AuthRequest, res) => {
  res.json({ challenge: deviceService.issueDeviceChallenge(req.userId!, req.sessionId!) });
});

router.post('/', authMiddleware, enrollmentLimit, async (req: AuthRequest, res) => {
  try {
    const body = registerSchema.parse(req.body);
    const { device, created, dirtyWorkspaceIds } = await deviceService.registerDevice(
      req.userId!,
      req.sessionId!,
      body.name,
      body.identityKey,
      body.challenge,
      body.proof,
      body.currentPassword,
    );
    const io = req.app.get('io') as SocketServer | undefined;
    if (created) io?.to(`user:${req.userId}`).emit('device:registered', device);
    for (const workspaceId of dirtyWorkspaceIds) {
      io?.to(`workspace:${workspaceId}`).emit('workspace:key-state-dirty', { workspaceId });
    }
    res.status(created ? 201 : 200).json(device);
  } catch (error: any) {
    if (error.message === 'SESSION_NOT_FOUND') {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
      return;
    }
    if (error.name === 'ZodError' || error.message === 'INVALID_IDENTITY_KEY') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid device data', statusCode: 400 });
      return;
    }
    if (error.message === 'IDENTITY_REVOKED') {
      res.status(409).json({ error: 'IDENTITY_REVOKED', message: 'This device identity has been revoked', statusCode: 409 });
      return;
    }
    if (['INVALID_DEVICE_PROOF', 'DEVICE_STEP_UP_REQUIRED', 'INVALID_CREDENTIALS'].includes(error.message)) {
      res.status(403).json({ error: 'DEVICE_STEP_UP_REQUIRED', message: 'Device verification is required', statusCode: 403 });
      return;
    }
    if (error.message === 'DEVICE_LIMIT_REACHED') {
      res.status(409).json({ error: 'DEVICE_LIMIT_REACHED', message: 'Revoke another device before adding one', statusCode: 409 });
      return;
    }
    if (error.message === 'DEVICE_IDENTITY_REVIEW_REQUIRED') {
      res.status(409).json({
        error: 'DEVICE_IDENTITY_REVIEW_REQUIRED',
        message: 'Device identity set requires administrator review',
        statusCode: 409,
      });
      return;
    }
    throw error;
  }
});

router.post('/:id/bind', authMiddleware, async (req: AuthRequest, res) => {
  if (!idSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
    return;
  }
  try {
    const body = proofSchema.parse(req.body);
    const device = await deviceService.bindDevice(
      req.params.id,
      req.userId!,
      req.sessionId!,
      body.challenge,
      body.proof,
    );
    res.json(device);
  } catch (error: any) {
    if (error.message === 'SESSION_NOT_FOUND') {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
      return;
    }
    if (error.message === 'DEVICE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
      return;
    }
    if (error.name === 'ZodError' || error.message === 'INVALID_DEVICE_PROOF') {
      res.status(403).json({ error: 'INVALID_DEVICE_PROOF', message: 'Device verification failed', statusCode: 403 });
      return;
    }
    throw error;
  }
});

router.get('/', authMiddleware, async (req: AuthRequest, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(await deviceService.getUserDevices(req.userId!));
});

router.delete('/:id', authMiddleware, revocationLimit, async (req: AuthRequest, res) => {
  if (!idSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
    return;
  }
  try {
    const { sessionIds, affectedWorkspaceIds } = await deviceService.revokeDevice(req.params.id, req.userId!, { ...decisionSchema.parse(req.body), actorDeviceId: req.deviceId! });
    const io = req.app.get('io') as SocketServer | undefined;
    for (const sessionId of sessionIds) io?.in(`session:${sessionId}`).disconnectSockets(true);
    io?.to(`user:${req.userId}`).emit('device:revoked', { deviceId: req.params.id });
    for (const workspaceId of affectedWorkspaceIds) {
      io?.to(`workspace:${workspaceId}`).emit('workspace:key-state-dirty', { workspaceId });
    }
    if (req.deviceId === req.params.id) res.setHeader('Set-Cookie', expiredSessionCookie());
    res.json({ success: true });
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: '入力内容を確認してください。', statusCode: 400 });
      return;
    }
    if (error.message === 'DEVICE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized', statusCode: 403 });
      return;
    }
    throw error;
  }
});

router.post('/:id/approve', authMiddleware, enrollmentLimit, async (req: AuthRequest, res, next) => {
  if (!idSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
    return;
  }
  try {
    const body = decisionSchema.parse(req.body);
    const result = await deviceService.approveDevice(req.userId!, req.deviceId!, idSchema.parse(req.params.id), body.head, body.signature);
    const io = req.app.get('io') as SocketServer | undefined;
    io?.to(`user:${req.userId}`).emit('device:approved', { deviceId: req.params.id });
    for (const workspaceId of result.dirtyWorkspaceIds) io?.to(`workspace:${workspaceId}`).emit('workspace:key-state-dirty', { workspaceId });
    res.json({ success: true });
  } catch (error: any) {
    if (!isAccountSecurityError(error)) { next(error); return; }
    res.status(error.message === 'DIRECTORY_CONFLICT' ? 409 : 403).json({ error: error.message === 'DIRECTORY_CONFLICT' ? 'DIRECTORY_CONFLICT' : 'DEVICE_APPROVAL_REQUIRED', message: '端末を確認できませんでした。表示を更新してお試しください。' });
  }
});

export default router;
