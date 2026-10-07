import { randomUUID } from 'node:crypto';
import { Router, type NextFunction } from 'express';
import type { WsAttentionNotification } from '@alparts/shared';
import { isAccountSecurityError } from '../security/account-errors.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/mls.service.js';
import { proposeMlsChannelEpoch } from '../services/key.service.js';
import { mlsEpochProposal, mlsPackage, mlsVersion } from './mls-schema.js';
const router = Router();
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
          message: 'The conversation could not be prepared. Try again.',
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
    const body = mlsPackage.extend({ version: mlsVersion }).parse(req.body);
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
        mlsVersion.parse(Number(req.params.version)),
      ),
    );
  }),
);
router.post(
  ['/channels/:id/mls/epochs', '/channels/:id/mls/epochs/fresh-start'],
  handle(async (req, res) => {
    const body = mlsEpochProposal.parse(req.body);
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
