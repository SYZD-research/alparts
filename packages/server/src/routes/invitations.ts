import { Router, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireWorkspacePermission } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as invitationService from '../services/invitation.service.js';
import { joinAuthorizedUserToWorkspaceRoom } from '../websocket/room-membership.js';
import { emitJoinedWorkspaceKeyState } from '../websocket/key-state.js';

const router = Router();
const uuid = z.string().uuid();
const createSchema = z.object({
  email: z.string().email().max(254).optional(),
  roleId: uuid.optional(),
  expiresInSeconds: z.number().int().min(300).max(30 * 24 * 60 * 60).default(7 * 24 * 60 * 60),
}).strict();
const acceptSchema = z.object({ token: z.string().min(32).max(512) }).strict();
const invitationMutationLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 100 });

router.post('/invitations/accept', authMiddleware, invitationMutationLimit, async (req: AuthRequest, res) => {
  try {
    const body = acceptSchema.parse(req.body);
    const result = await invitationService.acceptInvitation(req.userId!, body.token);
    const io = req.app.get('io') as SocketServer | undefined;
    if (io) await joinAuthorizedUserToWorkspaceRoom(io, req.userId!, result.workspaceId);
    io?.to(`workspace:${result.workspaceId}`).emit('workspace:member-added', {
      workspaceId: result.workspaceId,
      userId: req.userId,
    });
    void emitJoinedWorkspaceKeyState(io, req.userId!, result.workspaceId);
    res.json(result);
  } catch (error: any) {
    if (!sendInvitationError(res, error)) throw error;
  }
});

router.post(
  '/workspaces/:wid/invitations',
  authMiddleware,
  invitationMutationLimit,
  requireWorkspacePermission(Permissions.MANAGE_MEMBERS, 'wid'),
  async (req: AuthRequest, res) => {
    try {
      const body = createSchema.parse(req.body);
      res.status(201).json(await invitationService.createInvitation(req.params.wid, req.userId!, body));
    } catch (error: any) {
      if (!sendInvitationError(res, error)) throw error;
    }
  },
);

router.get(
  '/workspaces/:wid/invitations',
  authMiddleware,
  requireWorkspacePermission(Permissions.MANAGE_MEMBERS, 'wid'),
  async (req: AuthRequest, res) => {
    try {
      res.json(await invitationService.listInvitations(req.params.wid));
    } catch (error: any) {
      if (!sendInvitationError(res, error)) throw error;
    }
  },
);

router.delete(
  '/workspaces/:wid/invitations/:invitationId',
  authMiddleware,
  invitationMutationLimit,
  requireWorkspacePermission(Permissions.MANAGE_MEMBERS, 'wid'),
  async (req: AuthRequest, res) => {
    try {
      const invitationId = uuid.parse(req.params.invitationId);
      res.json(await invitationService.revokeInvitation(req.params.wid, invitationId, req.userId!));
    } catch (error: any) {
      if (!sendInvitationError(res, error)) throw error;
    }
  },
);

function sendInvitationError(res: Response, error: any): boolean {
  if (error?.name === 'ZodError' || error?.message === 'INVALID_INVITATION_EXPIRY') {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid invitation data', statusCode: 400 });
    return true;
  }
  if (error?.message === 'INVALID_INVITATION') {
    res.status(403).json({ error: 'INVALID_INVITATION', message: 'Invitation is invalid or no longer active', statusCode: 403 });
    return true;
  }
  if (['WORKSPACE_NOT_FOUND', 'INVITATION_NOT_FOUND'].includes(error?.message)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Invitation not found', statusCode: 404 });
    return true;
  }
  if (error?.message === 'NOT_AUTHORIZED' || error?.message === 'INVALID_INVITATION_ROLE') {
    res.status(403).json({ error: 'FORBIDDEN', message: 'Invitation cannot be created', statusCode: 403 });
    return true;
  }
  if (error?.message === 'INVITATION_NOT_ACTIVE') {
    res.status(409).json({ error: 'CONFLICT', message: 'Invitation is no longer active', statusCode: 409 });
    return true;
  }
  if (error?.message === 'WORKSPACE_MEMBER_LIMIT') {
    res.status(409).json({ error: 'WORKSPACE_MEMBER_LIMIT', message: 'Workspace member limit reached', statusCode: 409 });
    return true;
  }
  if (error?.message === 'WORKSPACE_MEMBERSHIP_LIMIT_REACHED') {
    res.status(409).json({ error: error.message, message: 'Workspace membership quota reached', statusCode: 409 });
    return true;
  }
  if (['INVITATION_ACTIVE_LIMIT_REACHED', 'INVITATION_RETENTION_LIMIT_REACHED'].includes(error?.message)) {
    res.status(409).json({ error: error.message, message: 'Workspace invitation quota reached', statusCode: 409 });
    return true;
  }
  if (error?.message === 'INVITATION_INVARIANT_EXCEEDED') {
    res.status(503).json({ error: error.message, message: 'Invitation invariant exceeded', statusCode: 503 });
    return true;
  }
  return false;
}

export default router;
