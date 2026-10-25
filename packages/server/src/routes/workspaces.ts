import { displayText } from '../security/display-text.js';
import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import * as workspaceService from '../services/workspace.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { stepUpRevalidation } from '../middleware/step-up.js';
import { requireWorkspaceMember, requireWorkspacePermission } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import {
  joinAuthorizedUserToChannelRoom,
  joinAuthorizedUserToWorkspaceRoom,
  leaveUserChannelRooms,
} from '../websocket/room-membership.js';
import { emitChannelKeyState, keyStateChannelIds } from '../websocket/key-state.js';
import { canonicalUuid } from '../security/canonical-id.js';

const router = Router();
const uuid = canonicalUuid;
const createSchema = z.object({
  name: displayText(),
  iconUrl: z.string().url().max(2048).refine((value) => new URL(value).protocol === 'https:').optional(),
}).strict();
const createLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 10 });

router.post('/', authMiddleware, createLimit, async (req: AuthRequest, res) => {
  try {
    const body = createSchema.parse(req.body);
    const workspace = await workspaceService.createWorkspace(body.name, req.userId!, body.iconUrl);
    // The creator's open connections joined their rooms before the workspace
    // existed; without this they would miss its members, profiles and channels
    // until they reconnect.
    const io = req.app.get('io') as SocketServer | undefined;
    if (io) await joinAuthorizedUserToWorkspaceRoom(io, req.userId!, workspace.id);
    res.status(201).json(workspace);
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid workspace data', statusCode: 400 });
      return;
    }
    if (['WORKSPACE_LIMIT_REACHED', 'WORKSPACE_MEMBERSHIP_LIMIT_REACHED'].includes(error.message)) {
      res.status(409).json({ error: error.message, message: 'Workspace quota reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    res.json(await workspaceService.getUserWorkspaces(req.userId!));
  } catch (error: any) {
    if (error.message === 'WORKSPACE_MEMBERSHIP_INVARIANT_EXCEEDED') {
      res.status(503).json({ error: error.message, message: 'Workspace membership invariant exceeded', statusCode: 503 });
      return;
    }
    throw error;
  }
});

router.get('/:id', authMiddleware, requireWorkspaceMember('id'), async (req: AuthRequest, res) => {
  const workspace = await workspaceService.getWorkspaceById(req.params.id);
  if (!workspace) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
    return;
  }
  res.json(workspace);
});

router.get('/:id/members', authMiddleware, requireWorkspaceMember('id'), async (req: AuthRequest, res) => {
  res.json(await workspaceService.getWorkspaceMembers(req.params.id));
});

router.delete('/:id/members/:userId', authMiddleware, requireWorkspacePermission(Permissions.KICK_MEMBERS, 'id'), async (req: AuthRequest, res) => {
  if (!uuid.safeParse(req.params.userId).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Member not found', statusCode: 404 });
    return;
  }
  try {
    const result = await workspaceService.removeMember(req.params.id, req.params.userId, req.userId!, stepUpRevalidation(req));
    const io = req.app.get('io') as SocketServer | undefined;
    io?.to(`user:${req.params.userId}`).emit('workspace:access-revoked', {
      workspaceId: req.params.id,
      membershipRemoved: true,
      // Include only channels this member could previously view. This lets an
      // inactive client erase persisted drafts/outbox/keys without disclosing
      // private channels that were never in its authorization scope.
      channelIds: result.revokedChannelIds,
    });
    io?.in(`user:${req.params.userId}`).socketsLeave(`workspace:${req.params.id}`);
    for (const channelId of result.allChannelIds) {
      if (io) leaveUserChannelRooms(io, req.params.userId, channelId);
    }
    // A private channel the member was last in went to the owner, who is told
    // of it like any new viewer.
    if (io) {
      for (const effect of result.roomEffects) {
        for (const gainedUserId of effect.gainedUserIds) {
          await joinAuthorizedUserToChannelRoom(io, gainedUserId, effect.channelId);
        }
        if (effect.gainedUserIds.length > 0) {
          io.to(`channel:${effect.channelId}`).emit('channel:permissions-updated', {
            channelId: effect.channelId,
            workspaceId: req.params.id,
          });
        }
      }
    }
    void emitChannelKeyState(io, keyStateChannelIds(result.roomEffects));
    io?.to(`workspace:${req.params.id}`).emit('workspace:member-removed', {
      workspaceId: req.params.id,
      userId: req.params.userId,
    });
    res.json({ success: true });
  } catch (error: any) {
    if (['WORKSPACE_NOT_FOUND', 'MEMBER_NOT_FOUND'].includes(error.message)) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Member not found', statusCode: 404 });
      return;
    }
    if (error.message === 'OWNER_CANNOT_BE_REMOVED') {
      res.status(409).json({ error: 'OWNER_REQUIRED', message: 'Transfer ownership before removing the owner', statusCode: 409 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
      return;
    }
    throw error;
  }
});

export default router;
