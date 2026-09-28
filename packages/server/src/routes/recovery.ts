import { Router, type NextFunction } from 'express';
import { isAccountSecurityError } from '../security/account-errors.js';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/recovery.service.js';
const router = Router();
router.use(authMiddleware);
router.use(
  rateLimit({
    windowMs: 60_000,
    max: 90,
    key: (req) => (req as AuthRequest).userId!,
  }),
);
const head = z
  .object({
    userId: z.string().uuid(),
    sequence: z.number().int().min(0).max(8192),
    hash: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();
const cursor = z
  .object({
    channelId: z.string().uuid(),
    version: z.coerce.number().int().min(1).max(1_000_000),
  })
  .strict();
const handler =
  (fn: (req: AuthRequest, res: any) => Promise<void>) =>
  async (req: AuthRequest, res: any, next: NextFunction) => {
    try {
      await fn(req, res);
    } catch (error) {
      if (!isAccountSecurityError(error)) {
        next(error);
        return;
      }
      res.status(403).json({
        error: 'RECOVERY_FAILED',
        message: '履歴を復元できませんでした。入力内容を確認してお試しください。',
      });
    }
  };
router.get(
  '/',
  handler(async (req, res) => {
    res.json(await service.recoveryConfiguration(req.userId!, req.sessionId!));
  }),
);
router.get(
  '/metadata',
  handler(async (req, res) => {
    res.json(await service.recoveryMetadata(req.userId!, req.sessionId!));
  }),
);
router.post(
  '/unlock',
  rateLimit({
    windowMs: 60 * 60_000,
    max: 10,
    key: (req) => (req as AuthRequest).userId!,
  }),
  handler(async (req, res) => {
    const body = z
      .object({
        generation: z.string().uuid(),
        token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      })
      .strict()
      .parse(req.body);
    res.json(
      await service.unlockRecovery(req.userId!, req.sessionId!, body.generation, body.token),
    );
  }),
);
router.post(
  '/access',
  handler(async (req, res) => {
    const body = z
      .object({
        generation: z.string().uuid(),
        accessTokenHash: z.string().regex(/^[a-f0-9]{64}$/),
      })
      .strict()
      .parse(req.body);
    await service.enrollRecoveryAccess(
      req.userId!,
      req.sessionId!,
      body.generation,
      body.accessTokenHash,
    );
    res.json({ success: true });
  }),
);
router.post(
  '/configure',
  handler(async (req, res) => {
    const body = z
      .object({
        generation: z.string().uuid(),
        signingKey: z.string().max(1024),
        encryptedSecret: z.string().min(64).max(4096),
        accessTokenHash: z.string().regex(/^[a-f0-9]{64}$/),
        head,
        signature: z.string().length(88),
      })
      .strict()
      .parse(req.body);
    await service.configureRecovery(req.userId!, req.sessionId!, body);
    req.app.get('io')?.to(`user:${req.userId}`).emit('account:security-changed');
    res.json({ success: true });
  }),
);
router.delete(
  '/',
  handler(async (req, res) => {
    await service.disableRecovery(
      req.userId!,
      req.sessionId!,
      z
        .object({ head, signature: z.string().length(88) })
        .strict()
        .parse(req.body),
    );
    req.app.get('io')?.to(`user:${req.userId}`).emit('account:security-changed');
    res.json({ success: true });
  }),
);
router.post(
  '/restore-device',
  rateLimit({
    windowMs: 60 * 60_000,
    max: 10,
    key: (req) => (req as AuthRequest).userId!,
  }),
  handler(async (req, res) => {
    const body = z
      .object({
        generation: z.string().uuid(),
        head,
        signature: z.string().length(88),
      })
      .strict()
      .parse(req.body);
    const result = await service.restoreDevice(req.userId!, req.sessionId!, body);
    req.app.get('io')?.to(`user:${req.userId}`).emit('account:security-changed');
    for (const workspaceId of result.dirtyWorkspaceIds)
      req.app
        .get('io')
        ?.to(`workspace:${workspaceId}`)
        .emit('workspace:key-state-dirty', { workspaceId });
    res.json({ success: true });
  }),
);
router.post(
  '/keys',
  handler(async (req, res) => {
    const record = z
      .object({
        generation: z.string().uuid(),
        channelId: z.string().uuid(),
        version: z.number().int().min(1).max(1_000_000),
        keyCommitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        ciphertext: z.string().min(64).max(512),
      })
      .strict();
    const body = z
      .union([record, z.object({ keys: z.array(record).min(1).max(64) }).strict()])
      .parse(req.body);
    await service.backupHistoryKeys(
      req.userId!,
      req.sessionId!,
      'keys' in body ? body.keys : [body],
    );
    res.json({ success: true });
  }),
);
router.get(
  '/keys',
  handler(async (req, res) => {
    res.json(
      await service.recoveryKeyPage(
        req.userId!,
        req.sessionId!,
        Object.keys(req.query).length ? cursor.parse(req.query) : undefined,
      ),
    );
  }),
);
router.get(
  '/candidates',
  handler(async (req, res) => {
    res.json(
      await service.historyBackupCandidates(
        req.userId!,
        req.sessionId!,
        Object.keys(req.query).length ? cursor.parse(req.query) : undefined,
      ),
    );
  }),
);
export default router;
