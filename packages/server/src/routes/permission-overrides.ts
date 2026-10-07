import { Router, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelPermission, requireWorkspacePermission } from '../middleware/rbac.js';
import * as overrideService from '../services/permission-override.service.js';
import type { ChannelViewerEffect } from '../services/authorization.service.js';
import { joinAuthorizedUserToChannelRoom, leaveUserChannelRooms } from '../websocket/room-membership.js';
import { emitChannelKeyState, keyStateChannelIds } from '../websocket/key-state.js';

const router = Router();
const uuid = z.string().uuid();
const permissionMask = z.number().int().min(0).max(0x7fffffff);
const authorizationRevision = z.string().regex(/^[a-f0-9]{64}$/);
const writeSchema = z.object({
  allowMask: permissionMask,
  denyMask: permissionMask,
  expectedRevision: z.number().int().min(0),
  expectedAuthorizationRevision: authorizationRevision,
}).strict();
const deleteSchema = z.object({
  expectedRevision: z.number().int().min(1),
  expectedAuthorizationRevision: authorizationRevision,
}).strict();
const previewSchema = z.discriminatedUnion('operation', [
  z.object({ operation: z.literal('upsert'), roleId: uuid, allowMask: permissionMask, denyMask: permissionMask }).strict(),
  z.object({ operation: z.literal('delete'), roleId: uuid }).strict(),
]);
const effectiveQuerySchema = z.object({ userId: uuid }).strict();

router.get(
  '/workspaces/:wid/categories/:targetId/permission-overrides',
  authMiddleware,
  requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'),
  listHandler('category'),
);
router.post(
  '/workspaces/:wid/categories/:targetId/permission-overrides/preview',
  authMiddleware,
  requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'),
  previewHandler('category'),
);
router.put(
  '/workspaces/:wid/categories/:targetId/permission-overrides/:roleId',
  authMiddleware,
  requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'),
  upsertHandler('category'),
);
router.delete(
  '/workspaces/:wid/categories/:targetId/permission-overrides/:roleId',
  authMiddleware,
  requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'),
  deleteHandler('category'),
);

router.get(
  '/workspaces/:wid/channels/:targetId/permission-overrides',
  authMiddleware,
  requireChannelPermission(Permissions.MANAGE_CHANNELS, 'targetId'),
  listHandler('channel'),
);
router.post(
  '/workspaces/:wid/channels/:targetId/permission-overrides/preview',
  authMiddleware,
  requireChannelPermission(Permissions.MANAGE_CHANNELS, 'targetId'),
  previewHandler('channel'),
);
router.put(
  '/workspaces/:wid/channels/:targetId/permission-overrides/:roleId',
  authMiddleware,
  requireChannelPermission(Permissions.MANAGE_CHANNELS, 'targetId'),
  upsertHandler('channel'),
);
router.delete(
  '/workspaces/:wid/channels/:targetId/permission-overrides/:roleId',
  authMiddleware,
  requireChannelPermission(Permissions.MANAGE_CHANNELS, 'targetId'),
  deleteHandler('channel'),
);
router.get(
  '/workspaces/:wid/channels/:targetId/permissions/effective',
  authMiddleware,
  requireChannelPermission(Permissions.MANAGE_CHANNELS, 'targetId'),
  async (req: AuthRequest, res) => {
    try {
      uuid.parse(req.params.wid);
      uuid.parse(req.params.targetId);
      const query = effectiveQuerySchema.parse(req.query);
      res.json(await overrideService.getEffectiveChannelPermissions(
        req.params.wid,
        req.params.targetId,
        query.userId,
        req.userId!,
      ));
    } catch (error: any) {
      if (!sendOverrideError(res, error)) throw error;
    }
  },
);

function listHandler(target: overrideService.OverrideTarget) {
  return async (req: AuthRequest, res: Response) => {
    try {
      uuid.parse(req.params.wid);
      uuid.parse(req.params.targetId);
      res.json(await overrideService.listPermissionOverrides(
        target,
        req.params.wid,
        req.params.targetId,
        req.userId!,
      ));
    } catch (error: any) {
      if (!sendOverrideError(res, error)) throw error;
    }
  };
}

function previewHandler(target: overrideService.OverrideTarget) {
  return async (req: AuthRequest, res: Response) => {
    try {
      uuid.parse(req.params.wid);
      uuid.parse(req.params.targetId);
      const body = previewSchema.parse(req.body);
      res.json(await overrideService.previewPermissionOverride(
        target,
        req.params.wid,
        req.params.targetId,
        req.userId!,
        body,
      ));
    } catch (error: any) {
      if (!sendOverrideError(res, error)) throw error;
    }
  };
}

function upsertHandler(target: overrideService.OverrideTarget) {
  return async (req: AuthRequest, res: Response) => {
    try {
      uuid.parse(req.params.wid);
      uuid.parse(req.params.targetId);
      const roleId = uuid.parse(req.params.roleId);
      const body = writeSchema.parse(req.body);
      const result = await overrideService.upsertPermissionOverride(
        target,
        req.params.wid,
        req.params.targetId,
        roleId,
        req.userId!,
        body,
      );
      await applyRealtimeEffects(req, result.roomEffects);
      res.json(result);
    } catch (error: any) {
      if (!sendOverrideError(res, error)) throw error;
    }
  };
}

function deleteHandler(target: overrideService.OverrideTarget) {
  return async (req: AuthRequest, res: Response) => {
    try {
      uuid.parse(req.params.wid);
      uuid.parse(req.params.targetId);
      const roleId = uuid.parse(req.params.roleId);
      const body = deleteSchema.parse(req.body);
      const result = await overrideService.deletePermissionOverride(
        target,
        req.params.wid,
        req.params.targetId,
        roleId,
        req.userId!,
        body.expectedRevision,
        body.expectedAuthorizationRevision,
      );
      await applyRealtimeEffects(req, result.roomEffects);
      res.json(result);
    } catch (error: any) {
      if (!sendOverrideError(res, error)) throw error;
    }
  };
}

async function applyRealtimeEffects(req: AuthRequest, effects: ChannelViewerEffect[]) {
  const io = req.app.get('io') as SocketServer | undefined;
  if (!io) return;
  for (const effect of effects) {
    for (const userId of effect.lostUserIds) {
      io.to(`user:${userId}`).emit('channel:access-revoked', {
        workspaceId: req.params.wid,
        channelId: effect.channelId,
      });
      leaveUserChannelRooms(io, userId, effect.channelId);
    }
    for (const userId of effect.gainedUserIds) {
      await joinAuthorizedUserToChannelRoom(io, userId, effect.channelId);
    }
    io.to(`channel:${effect.channelId}`).emit('channel:permissions-updated', {
      channelId: effect.channelId,
      workspaceId: req.params.wid,
    });
  }
  void emitChannelKeyState(io, keyStateChannelIds(effects));
  io.to(`workspace:${req.params.wid}`).emit('workspace:permissions-updated', { workspaceId: req.params.wid });
}

function sendOverrideError(res: Response, error: any): boolean {
  if (error?.name === 'ZodError' || ['INVALID_OVERRIDE', 'INVALID_OVERRIDE_PERMISSIONS'].includes(error?.message)) {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid permission override', statusCode: 400 });
    return true;
  }
  if (['TARGET_NOT_FOUND', 'ROLE_NOT_FOUND', 'MEMBER_NOT_FOUND'].includes(error?.message)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Permission override target not found', statusCode: 404 });
    return true;
  }
  if (error?.message === 'MEMBER_HIERARCHY') {
    res.status(403).json({ error: 'MEMBER_HIERARCHY', message: 'Change would reduce a higher-ranked member', statusCode: 403 });
    return true;
  }
  if (error?.message === 'NOT_AUTHORIZED') {
    res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
    return true;
  }
  if (error?.message === 'OVERRIDE_NOT_FOUND') {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Permission override not found', statusCode: 404 });
    return true;
  }
  if (error?.message === 'STALE_OVERRIDE' || error?.code === '23505') {
    res.status(409).json({ error: 'STALE_OVERRIDE', message: 'Permission override preview is stale', statusCode: 409 });
    return true;
  }
  if (error?.message === 'STALE_PREVIEW') {
    res.status(409).json({ error: 'STALE_PREVIEW', message: 'Authorization preview is stale', statusCode: 409 });
    return true;
  }
  return false;
}

export default router;
