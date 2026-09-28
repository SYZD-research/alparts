import { displayText } from '../security/display-text.js';
import { Router, type NextFunction } from 'express';
import { isAccountSecurityError } from '../security/account-errors.js';
import { z } from 'zod';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/passkey.service.js';
import { sessionCookie } from '../security/cookies.js';
import { config } from '../config/index.js';

const router = Router();
router.use('/passkeys', rateLimit({ windowMs: 15 * 60_000, max: 40 }));
router.use(
  '/step-up',
  authMiddleware,
  rateLimit({
    windowMs: 15 * 60_000,
    max: 120,
    key: (req) => (req as AuthRequest).userId!,
  }),
);
const responseSchema = z
  .object({
    id: z.string().min(1).max(2048),
    response: z.object({}).passthrough(),
  })
  .passthrough()
  .refine((v) => JSON.stringify(v).length <= 16_384);
const assertionSchema = z.object({ id: z.string().uuid(), response: responseSchema }).strict();
const purposeSchema = z
  .string()
  .regex(/^(POST|PUT|PATCH|DELETE) \/api\/[A-Za-z0-9/_%.-]+ [A-Za-z0-9_-]{43}$/)
  .max(512);
const handle =
  (handler: (req: AuthRequest, res: any) => Promise<void>) =>
  async (req: AuthRequest, res: any, next: NextFunction) => {
    try {
      await handler(req, res);
    } catch (error: any) {
      if (!isAccountSecurityError(error)) {
        next(error);
        return;
      }
      if (error.message === 'LAST_PASSKEY') {
        res.status(409).json({
          error: 'LAST_PASSKEY',
          message: '別のパスキーを登録してから削除してください。',
        });
        return;
      }
      if (error.message === 'DEVICE_APPROVAL_REQUIRED') {
        res.status(403).json({
          error: 'DEVICE_APPROVAL_REQUIRED',
          message: '承認済みの端末で操作してください。',
        });
        return;
      }
      // Parser, verifier, challenge and unknown credential failures have one public result.
      res.status(403).json({
        error: 'AUTHENTICATION_FAILED',
        message: '本人確認を完了できませんでした。もう一度お試しください。',
      });
    }
  };
router.get(
  '/passkeys/vault', authMiddleware,
  handle(async (_req, res) => { res.json({ rpId: config.webauthn.rpId }); }),
);
router.get(
  '/passkeys',
  authMiddleware,
  handle(async (req, res) => {
    res.json(await service.listPasskeys(req.userId!));
  }),
);
router.post(
  '/passkeys/register/options',
  authMiddleware,
  handle(async (req, res) => {
    res.json(await service.registrationOptions(req.userId!, req.sessionId!));
  }),
);
router.post(
  '/passkeys/register/verify',
  authMiddleware,
  handle(async (req, res) => {
    const body = assertionSchema.extend({ name: displayText(80) }).parse(req.body);
    await service.finishRegistration(
      req.userId!,
      req.sessionId!,
      body.id,
      body.name,
      body.response as unknown as RegistrationResponseJSON,
    );
    req.app.get('io')?.to(`user:${req.userId}`).emit('account:security-changed');
    res.json({ success: true });
  }),
);
router.delete(
  '/passkeys/:id',
  authMiddleware,
  handle(async (req, res) => {
    await service.deletePasskey(req.userId!, z.string().max(2048).parse(req.params.id));
    res.json({ success: true });
  }),
);
router.post(
  '/passkeys/login/options',
  handle(async (_req, res) => {
    res.json(await service.authenticationOptions('login', null, null));
  }),
);
router.post(
  '/passkeys/login/verify',
  handle(async (req, res) => {
    const body = assertionSchema.parse(req.body);
    const result = await service.passkeyLogin(
      body.id,
      body.response as unknown as AuthenticationResponseJSON,
    );
    res.setHeader('Set-Cookie', sessionCookie(result.token, config.jwt.expiresInSeconds));
    res.json({ user: result.user });
  }),
);
router.post(
  '/step-up/options',
  authMiddleware,
  handle(async (req, res) => {
    const purpose = purposeSchema.parse(req.body.purpose);
    res.json(await service.authenticationOptions(purpose, req.userId!, req.sessionId!));
  }),
);
router.post(
  '/step-up/verify',
  authMiddleware,
  handle(async (req, res) => {
    const body = z
      .object({
        id: z.string().uuid(),
        purpose: purposeSchema,
        response: responseSchema.optional(),
        password: z
          .string()
          .min(1)
          .max(72)
          .refine((p) => Buffer.byteLength(p) <= 72)
          .optional(),
      })
      .strict()
      .parse(req.body);
    res.json(
      await service.finishStepUp(
        req.userId!,
        req.sessionId!,
        body.id,
        body.purpose,
        body.response as unknown as AuthenticationResponseJSON | undefined,
        body.password,
      ),
    );
  }),
);
export default router;
