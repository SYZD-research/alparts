import { randomUUID } from 'node:crypto';
import { Router, type NextFunction } from 'express';
import type { WsAttentionNotification } from '@alparts/shared';
import { isAccountSecurityError } from '../security/account-errors.js';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/mls.service.js';
import { proposeMlsChannelEpoch } from '../services/key.service.js';
const router = Router();
const encoded = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/);
const signature = encoded.length(88);
const version = z.number().int().min(1).max(1_000_000);
const pkg = z
  .object({
    packageId: z.string().uuid(),
    keyPackage: encoded.max(4096),
    signature,
  })
  .strict();
const member = pkg
  .extend({
    deviceId: z.string().uuid(),
    userId: z.string().uuid(),
    identityKey: z.string().max(16_384),
  })
  .strict();
const epoch = z
  .object({
    channelId: z.string().uuid(),
    version,
    previousVersion: z.number().int().min(0).max(1_000_000),
    previousTranscript: z.string().regex(/^[a-f0-9]{64}$/),
    keyCommitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    welcome: z.string().max(512_000),
    commit: encoded.max(128_000),
    roster: z.array(member).min(1).max(400),
    directoryHeads: z
      .array(
        z
          .object({
            userId: z.string().uuid(),
            sequence: z.number().int().min(1).max(8192),
            hash: z.string().regex(/^[a-f0-9]{64}$/),
          })
          .strict(),
      )
      .min(1)
      .max(50),
    distributorDeviceId: z.string().uuid(),
    signature,
  })
  .strict();
router.use(
  '/channels/:id/mls',
  authMiddleware,
  rateLimit({
    windowMs: 60_000,
    max: 90,
    key: (req) => (req as AuthRequest).userId!,
  }),
  requireChannelAccess('id'),
);
const handle =
  (fn: (req: AuthRequest, res: any) => Promise<void>) =>
  async (req: AuthRequest, res: any, next: NextFunction) => {
    try {
      if (!req.deviceId) {
        res.sendStatus(403);
        return;
      }
      await fn(req, res);
    } catch (error: any) {
      if (!isAccountSecurityError(error)) {
        next(error);
        return;
      }
      res
        .status(
          ['MLS_CONFLICT', 'KEY_EPOCH_PENDING'].includes(error.message) || error.code === '23505'
            ? 409
            : 403,
        )
        .json({
          error: 'GROUP_STATE_CHANGED',
          message: '会話の準備を完了できませんでした。もう一度お試しください。',
        });
    }
  };
router.get(
  '/channels/:id/mls/packages',
  handle(async (req, res) => {
    res.json(await service.groupPackages(req.params.id, req.userId!, req.deviceId!));
  }),
);
router.post(
  '/channels/:id/mls/packages',
  handle(async (req, res) => {
    const body = pkg.extend({ version }).parse(req.body);
    const created = await service.publishKeyPackage(
      req.params.id,
      req.userId!,
      req.deviceId!,
      body.version,
      {
        packageId: body.packageId,
        keyPackage: body.keyPackage,
        signature: body.signature,
      },
    );
    if (created)
      req.app
        .get('io')
        ?.to(`channel:${req.params.id}`)
        .emit('channel:key-rotation-required', { channelId: req.params.id });
    res.json({ success: true });
  }),
);
router.get(
  '/channels/:id/mls/epochs/:version',
  handle(async (req, res) => {
    res.json(
      await service.getMlsEpoch(
        req.params.id,
        req.userId!,
        req.deviceId!,
        version.parse(Number(req.params.version)),
      ),
    );
  }),
);
router.post(
  ['/channels/:id/mls/epochs', '/channels/:id/mls/epochs/fresh-start'],
  handle(async (req, res) => {
    const body = z
      .object({
        epoch,
        freshStartSignature: signature.optional(),
        keys: z
          .array(
            z
              .object({
                deviceId: z.string().uuid(),
                encryptedKey: encoded.max(2048),
                signature,
              })
              .strict(),
          )
          .min(1)
          .max(400),
      })
      .strict()
      .parse(req.body);
    if (body.epoch.channelId !== req.params.id) {
      res.sendStatus(400);
      return;
    }
    const fresh = req.path.endsWith('/fresh-start');
    if (fresh !== Boolean(body.freshStartSignature)) {
      res.sendStatus(400);
      return;
    }
    const { notifyManagerUserIds, workspaceId, ...result } = await proposeMlsChannelEpoch(
      req.userId!,
      req.deviceId!,
      body.epoch,
      body.keys,
      body.freshStartSignature,
      req.stepUpProof,
    );
    const io = req.app.get('io');
    io?.to(`channel:${req.params.id}`).emit('channel:key-rotation-required', { channelId: req.params.id });
    for (const managerId of notifyManagerUserIds) {
      io?.to(`user:${managerId}`).emit('attention:new', {
        notificationId: randomUUID(),
        workspaceId,
        channelId: req.params.id,
        kind: 'channel-restarted',
      } satisfies WsAttentionNotification);
    }
    res.status(201).json(result);
  }),
);
export default router;
