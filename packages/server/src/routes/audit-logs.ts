import { Router } from 'express';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireWorkspacePermission } from '../middleware/rbac.js';
import { rateLimit, requestSource } from '../middleware/rate-limit.js';
import * as auditLogService from '../services/audit-log.service.js';

const router = Router();
const uuid = z.string().uuid();
const listQuery = z.object({
  cursor: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
}).strict();
const auditReadLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const integrityReadLimit = rateLimit({
  windowMs: 60_000,
  max: 5,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});

router.post(
  '/workspaces/:wid/audit-logs',
  authMiddleware,
  auditReadLimit,
  requireWorkspacePermission(Permissions.VIEW_AUDIT_LOG, 'wid'),
  async (req: AuthRequest, res) => {
    try {
      const query = listQuery.parse(req.query);
      res.json(await auditLogService.listWorkspaceAuditLogs(req.params.wid, req.userId!, query));
    } catch (error: any) {
      if (error?.name === 'ZodError' || error?.message === 'INVALID_CURSOR') {
        res.status(400).json({ error: 'VALIDATION', message: 'Invalid audit log query', statusCode: 400 });
        return;
      }
      throw error;
    }
  },
);

router.post(
  '/workspaces/:wid/audit-integrity',
  authMiddleware,
  integrityReadLimit,
  requireWorkspacePermission(Permissions.VIEW_AUDIT_LOG, 'wid'),
  async (req: AuthRequest, res) => {
    res.json(await auditLogService.getAuditIntegrity(req.params.wid, req.userId!));
  },
);

export default router;
