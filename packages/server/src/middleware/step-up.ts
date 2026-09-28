import type { NextFunction, Response } from 'express';
import { isSensitiveAction } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from './auth.js';
import { consumeStepUp } from '../services/passkey.service.js';

import { actionPurpose } from '../security/action-purpose.js';
export { actionPurpose } from '../security/action-purpose.js';
export async function sensitiveActionBoundary(req: AuthRequest, res: Response, next: NextFunction) {
  // Match the pathname Express routes, including absolute-form request targets.
  const path = req.baseUrl + req.path;
  if (!isSensitiveAction(req.method, path)) {
    next();
    return;
  }
  await authMiddleware(req, res, async () => {
    const purpose = actionPurpose(req.method, path, req.body);
    const token = req.get('X-Alparts-Step-Up');
    try {
      const proof =
        req.originalUrl.startsWith('/') &&
        !req.originalUrl.startsWith('//') &&
        token &&
        /^[A-Za-z0-9_-]{43}$/.test(token)
          ? await consumeStepUp(req.sessionId!, purpose, token)
          : null;
      if (!proof) {
        res.status(428).json({
          error: 'STEP_UP_REQUIRED',
          purpose,
          message: '続けるには本人確認が必要です。',
        });
        return;
      }
      req.stepUpProof = proof;
      next();
    } catch (error) {
      next(error);
    }
  });
}
