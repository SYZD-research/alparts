import { Router, type NextFunction } from 'express';
import { isAccountSecurityError } from '../security/account-errors.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/mls.service.js';
import { mlsVersion } from './mls-schema.js';
const router = Router();
// Per-epoch groups (protocol 3) only remain readable as history. Their write
// routes ask open tabs from before continuous groups to reload.
const updateRequired = (_req: unknown, res: any) => {
  res.status(410).json({ error: 'UPDATE_REQUIRED', message: 'Update the application and try again', statusCode: 410 });
};
router.get('/channels/:id/mls/packages', authMiddleware, updateRequired);
router.post('/channels/:id/mls/packages', authMiddleware, updateRequired);
router.post(['/channels/:id/mls/epochs', '/channels/:id/mls/epochs/fresh-start'], authMiddleware, updateRequired);
router.use(
  '/channels/:id/mls/epochs',
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
      // A version this device may not read is as unknown as one that does not exist.
      if (error instanceof Error && (error.message === 'MLS_NOT_FOUND' || error.message === 'CHANNEL_NOT_FOUND')) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Not found', statusCode: 404 });
        return;
      }
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
export default router;
