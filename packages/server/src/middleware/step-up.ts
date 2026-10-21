import type { NextFunction, Response } from 'express';
import { isSensitiveRequest } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from './auth.js';
import { assertStepUpStillValid, consumeStepUp } from '../services/passkey.service.js';

import { actionPurpose } from '../security/action-purpose.js';
export { actionPurpose } from '../security/action-purpose.js';

/**
 * Returns the T2 revalidation callback for a request that passed the
 * step-up boundary, or undefined when the request carried no proof (for
 * example a PUT /channels body with no sensitive fields). Mutating service
 * functions call it inside their auditedTransaction so a grant consumed in
 * T1 cannot still commit after the session or credential was revoked.
 */
export function stepUpRevalidation(req: AuthRequest): ((tx: any) => Promise<void>) | undefined {
  const proof = req.stepUpProof;
  if (!proof) return undefined;
  return (tx) => assertStepUpStillValid(tx, proof, req.userId!, req.sessionId!);
}

export async function sensitiveActionBoundary(req: AuthRequest, res: Response, next: NextFunction) {
  // Match the pathname Express routes, including absolute-form request targets.
  const path = req.baseUrl + req.path;
  if (!isSensitiveRequest(req.method, path, req.body)) {
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
          message: 'Confirm your identity to continue.',
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
