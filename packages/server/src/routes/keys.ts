import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import * as keyService from '../services/key.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import { MAX_KEY_RECIPIENTS } from '../security/limits.js';
import { rateLimit } from '../middleware/rate-limit.js';

const router = Router();
const wrappedKey = z.string().min(100).max(2048).regex(/^[A-Za-z0-9+/]+={0,2}$/);
const distributionSchema = z.object({
  version: z.number().int().min(1).max(1_000_000),
  keyCommitment: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  keys: z.array(z.object({
    deviceId: z.string().uuid(),
    encryptedKey: wrappedKey,
    signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
  }).strict()).min(1).max(MAX_KEY_RECIPIENTS),
}).strict();
const acknowledgementSchema = z.object({
  deliveryId: z.string().uuid(),
  signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
}).strict();
const abortSchema = z.object({
  version: z.number().int().min(1).max(1_000_000),
  keyCommitment: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
}).strict();
const keyMutationLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  key: (req) => `${(req as AuthRequest).userId || req.ip || 'unknown'}:${req.params.id || 'unknown'}`,
});
const keyAbortLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  key: (req) => `${(req as AuthRequest).userId || req.ip || 'unknown'}:${req.params.id || 'unknown'}`,
});

router.get('/channels/:id/key-recipients', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.json(await keyService.getKeyRecipients(req.params.id, req.userId!, req.deviceId ?? undefined));
  } catch (error: any) {
    if (error.message === 'KEY_RECIPIENT_LIMIT') {
      res.status(409).json({ error: 'KEY_RECIPIENT_LIMIT', message: 'Channel key recipient limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/channels/:id/keys', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  if (!req.deviceId) {
    res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
    return;
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json(await keyService.getDeviceChannelKeys(req.params.id, req.userId!, req.deviceId));
});

router.get('/channels/:id/device-directory', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(await keyService.getChannelDeviceDirectory(req.params.id, req.userId!));
});

router.post('/channels/:id/keys', authMiddleware, keyMutationLimit, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  if (!req.deviceId) {
    res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
    return;
  }
  try {
    const body = distributionSchema.parse(req.body);
    const result = await keyService.distributeChannelKeys(
      req.params.id,
      req.userId!,
      req.deviceId,
      body.version,
      body.keyCommitment,
      body.keys,
    );
    if (result.mode === 'proposal') emitKeyStateChanged(req, req.params.id);
    const { mode: _mode, ...response } = result;
    res.status(201).json(response);
  } catch (error: any) {
    if (error.name === 'ZodError' || [
      'INVALID_KEY_RECIPIENTS',
      'INCOMPLETE_KEY_DISTRIBUTION',
      'INVALID_KEY_VERSION',
      'INVALID_KEY_SIGNATURE',
      'KEY_COMMITMENT_MISMATCH',
    ].includes(error.message)) {
      res.status(400).json({ error: 'INVALID_KEY_DISTRIBUTION', message: 'Invalid key distribution', statusCode: 400 });
      return;
    }
    if (['KEY_ROTATION_FORBIDDEN', 'KEY_DISTRIBUTION_FORBIDDEN'].includes(error.message)) {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Key distribution is not permitted', statusCode: 403 });
      return;
    }
    if ([
      'KEY_ALREADY_DISTRIBUTED',
      'KEY_DISTRIBUTION_FAILED',
      'KEY_DELIVERY_LIMIT',
      'KEY_EPOCH_PENDING',
      'KEY_ROTATION_NOT_REQUIRED',
      'KEY_CANDIDATE_IMMUTABLE',
    ].includes(error.message) || error?.code === '23505') {
      res.status(409).json({ error: 'CONFLICT', message: 'Key was already distributed', statusCode: 409 });
      return;
    }
    if (error.message === 'KEY_RECIPIENT_LIMIT') {
      res.status(409).json({ error: 'KEY_RECIPIENT_LIMIT', message: 'Channel key recipient limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.post('/channels/:id/keys/acknowledge', authMiddleware, keyMutationLimit, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  if (!req.deviceId) {
    res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
    return;
  }
  try {
    const body = acknowledgementSchema.parse(req.body);
    const result = await keyService.acknowledgeChannelKey(
      req.params.id,
      req.userId!,
      req.deviceId,
      body.deliveryId,
      body.signature,
    );
    if (result.activated || result.status === 'aborted') emitKeyStateChanged(req, req.params.id);
    res.json(result);
  } catch (error: any) {
    if (error.name === 'ZodError' || [
      'INVALID_KEY_ACKNOWLEDGEMENT',
      'INVALID_KEY_DELIVERY',
      'INVALID_KEY_VERSION',
    ].includes(error.message)) {
      res.status(400).json({ error: 'INVALID_KEY_ACKNOWLEDGEMENT', message: 'Invalid key acknowledgement', statusCode: 400 });
      return;
    }
    if (error.message === 'DEVICE_REQUIRED') {
      res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
      return;
    }
    if (error.message === 'KEY_ALREADY_ACKNOWLEDGED') {
      res.status(409).json({ error: 'CONFLICT', message: 'A delivery was already acknowledged', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.post('/channels/:id/keys/abort', authMiddleware, keyAbortLimit, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  if (!req.deviceId) {
    res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
    return;
  }
  try {
    const body = abortSchema.parse(req.body);
    const result = await keyService.abortPendingChannelKey(
      req.params.id,
      req.userId!,
      req.deviceId,
      body.version,
      body.keyCommitment,
      body.signature,
    );
    emitKeyStateChanged(req, req.params.id);
    res.json(result);
  } catch (error: any) {
    if (error.name === 'ZodError' || ['INVALID_KEY_ABORT', 'INVALID_KEY_VERSION'].includes(error.message)) {
      res.status(400).json({ error: 'INVALID_KEY_ABORT', message: 'Invalid key epoch abort', statusCode: 400 });
      return;
    }
    if (error.message === 'KEY_ABORT_FORBIDDEN') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Key epoch abort is not permitted', statusCode: 403 });
      return;
    }
    if (error.message === 'DEVICE_REQUIRED') {
      res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
      return;
    }
    if (error.message === 'KEY_ABORT_FAILED') {
      res.status(409).json({ error: 'CONFLICT', message: 'Key epoch state changed', statusCode: 409 });
      return;
    }
    throw error;
  }
});

function emitKeyStateChanged(req: AuthRequest, channelId: string): void {
  const io = req.app.get('io') as SocketServer | undefined;
  io?.to(`channel:${channelId}`).emit('channel:key-rotation-required', { channelId });
}

export default router;
