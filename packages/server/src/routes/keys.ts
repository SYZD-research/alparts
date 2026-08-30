import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import * as keyService from '../services/key.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import {
  MAX_DEVICE_DIRECTORY_LOOKUP_IDS,
  MAX_KEY_RECIPIENTS,
  MAX_KEY_VERSION_LOOKUP_IDS,
} from '../security/limits.js';
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
const keyQuerySchema = z.object({
  scope: z.literal('current').optional(),
  version: z.coerce.number().int().min(1).max(1_000_000).optional(),
  versions: z.string()
    .min(1)
    .max(MAX_KEY_VERSION_LOOKUP_IDS * 8)
    .transform((value) => value.split(',').map(Number))
    .pipe(z.array(z.number().int().min(1).max(1_000_000)).min(1).max(MAX_KEY_VERSION_LOOKUP_IDS))
    .refine((values) => new Set(values).size === values.length, 'Key versions must be unique')
    .optional(),
}).strict().refine((value) => (
  [value.scope, value.version, value.versions].filter((candidate) => candidate !== undefined).length <= 1
));
const deviceDirectoryQuerySchema = z.object({
  ids: z.string()
    .min(36)
    .max(MAX_DEVICE_DIRECTORY_LOOKUP_IDS * 37 - 1)
    .transform((value) => value.split(','))
    .pipe(z.array(z.string().uuid()).min(1).max(MAX_DEVICE_DIRECTORY_LOOKUP_IDS))
    .refine((values) => new Set(values).size === values.length, 'Device IDs must be unique')
    .optional(),
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
  try {
    if (!req.deviceId) {
      res.status(428).json({ error: 'DEVICE_REQUIRED', message: 'A bound device is required', statusCode: 428 });
      return;
    }
    const query = keyQuerySchema.parse(req.query);
    res.setHeader('Cache-Control', 'no-store');
    const legacyWindow = query.scope === undefined
      && query.version === undefined
      && query.versions === undefined;
    if (legacyWindow) {
      res.setHeader('Deprecation', 'true');
      res.setHeader('Warning', '299 alparts "Unscoped key history is a bounded compatibility window; reload the client"');
    }
    const requestedVersions = query.version === undefined
      ? query.versions
      : [query.version];
    res.json(await keyService.getDeviceChannelKeys(
      req.params.id,
      req.userId!,
      req.deviceId,
      requestedVersions,
      legacyWindow,
    ));
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid key version', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.get('/channels/:id/device-directory', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    const query = deviceDirectoryQuerySchema.parse(req.query);
    res.setHeader('Cache-Control', 'no-store');
    if (query.ids === undefined) {
      res.setHeader('Deprecation', 'true');
      res.setHeader('Warning', '299 alparts "Unscoped device history is bounded; reload the client"');
    }
    res.json(await keyService.getChannelDeviceDirectory(req.params.id, req.userId!, query.ids));
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'DEVICE_DIRECTORY_LOOKUP_LIMIT') {
      res.status(400).json({
        error: 'VALIDATION',
        message: 'Invalid bounded device-directory request',
        statusCode: 400,
      });
      return;
    }
    if (error.message === 'DEVICE_DIRECTORY_INVARIANT_EXCEEDED') {
      res.status(409).json({
        error: 'DEVICE_DIRECTORY_LIMIT',
        message: 'Legacy device history exceeds the compatibility window; reload the client',
        statusCode: 409,
      });
      return;
    }
    throw error;
  }
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
