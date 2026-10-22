import { Router, type NextFunction } from 'express';
import { isAccountSecurityError } from '../security/account-errors.js';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { stepUpRevalidation } from '../middleware/step-up.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/recovery.service.js';
import { emitUserKeyState } from '../websocket/key-state.js';
import { canonicalUuid } from '../security/canonical-id.js';
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
    userId: canonicalUuid,
    sequence: z.number().int().min(0).max(8192),
    hash: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();
const cursor = z
  .object({
    channelId: canonicalUuid,
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
        message: 'History could not be restored. Check the input and try again.',
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
        generation: canonicalUuid,
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
        generation: canonicalUuid,
        accessTokenHash: z.string().regex(/^[a-f0-9]{64}$/),
      })
      .strict()
      .parse(req.body);
    await service.enrollRecoveryAccess(
      req.userId!,
      req.sessionId!,
      body.generation,
      body.accessTokenHash,
      stepUpRevalidation(req),
    );
    res.json({ success: true });
  }),
);
router.post(
  '/configure',
  handler(async (req, res) => {
    const body = z
      .object({
        generation: canonicalUuid,
        signingKey: z.string().max(1024),
        encryptedSecret: z.string().min(64).max(4096),
        accessTokenHash: z.string().regex(/^[a-f0-9]{64}$/),
        head,
        signature: z.string().length(88),
      })
      .strict()
      .parse(req.body);
    await service.configureRecovery(req.userId!, req.sessionId!, body, stepUpRevalidation(req));
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
      stepUpRevalidation(req),
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
        generation: canonicalUuid,
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
    void emitUserKeyState(req.app.get('io'), req.userId!, result.dirtyWorkspaceIds);
    res.json({ success: true });
  }),
);
router.post(
  '/keys',
  handler(async (req, res) => {
    const record = z
      .object({
        generation: canonicalUuid,
        channelId: canonicalUuid,
        version: z.number().int().min(1).max(1_000_000),
        keyCommitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        ciphertext: z.string().min(64).max(512),
        // Absent from clients that predate signed records.
        signature: z.string().length(88).optional(),
      })
      .strict();
    const body = z
      .union([record, z.object({ keys: z.array(record).min(1).max(64) }).strict()])
      .parse(req.body);
    const records = 'keys' in body ? body.keys : [body];
    const signed = records.filter(
      (entry): entry is typeof entry & { signature: string } => entry.signature !== undefined,
    );
    if (signed.length !== records.length) {
      res.status(410).json({ error: 'UPDATE_REQUIRED', message: 'Update the application and try again', statusCode: 410 });
      return;
    }
    res.json({ results: await service.backupHistoryKeys(req.userId!, req.sessionId!, signed) });
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
