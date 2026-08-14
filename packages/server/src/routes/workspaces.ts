import { Router } from 'express';
import { z } from 'zod';
import * as workspaceService from '../services/workspace.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Permissions } from '@alparts/shared';

const router = Router();

const createSchema = z.object({
  name: z.string().min(1).max(100),
  iconUrl: z.string().url().optional(),
});

router.post('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = createSchema.parse(req.body);
    const workspace = await workspaceService.createWorkspace(body.name, req.userId!, body.iconUrl);
    res.status(201).json(workspace);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const workspaces = await workspaceService.getUserWorkspaces(req.userId!);
    res.json(workspaces);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const workspace = await workspaceService.getWorkspaceById(req.params.id);
    if (!workspace) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
      return;
    }
    res.json(workspace);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/:id/members', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const members = await workspaceService.getWorkspaceMembers(req.params.id);
    res.json(members);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.post('/:id/invite', authMiddleware, requirePermission(Permissions.MANAGE_MEMBERS), async (req: AuthRequest, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      res.status(400).json({ error: 'VALIDATION', message: 'userId is required', statusCode: 400 });
      return;
    }
    const member = await workspaceService.addMember(req.params.id, userId, req.userId!);
    res.status(201).json(member);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
