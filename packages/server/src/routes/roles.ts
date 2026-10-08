import { displayText } from '../security/display-text.js';
import { Router, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import {
  getUserPermissions,
  requireWorkspaceMember,
  requireWorkspaceMembership,
  requireWorkspacePermission,
} from '../middleware/rbac.js';
import * as roleService from '../services/role.service.js';
import {
  joinAuthorizedUserToChannelRoom,
  joinAuthorizedUserToWorkspaceRoom,
  leaveUserChannelRooms,
} from '../websocket/room-membership.js';
import { emitChannelKeyState, keyStateChannelIds } from '../websocket/key-state.js';

const router = Router();
const uuid = z.string().uuid();
const permissionMask = z.number().int().min(0).max(0x7fffffff);
const position = z.number().int().min(0).max(1_000_000);
const authorizationRevision = z.string().regex(/^[a-f0-9]{64}$/);
const createRoleSchema = z.object({
  name: displayText(),
  permissions: permissionMask,
  position,
}).strict();
const updateRoleSchema = z.object({
  name: displayText().optional(),
  permissions: permissionMask.optional(),
  position: position.optional(),
  expectedAuthorizationRevision: authorizationRevision,
}).strict().refine((value) => Object.keys(value).some((key) => key !== 'expectedAuthorizationRevision'));
const authorizationRevisionSchema = z.object({ expectedAuthorizationRevision: authorizationRevision }).strict();
const previewSchema = z.discriminatedUnion('operation', [
  z.object({ operation: z.literal('role.update'), roleId: uuid, permissions: permissionMask }).strict(),
  z.object({ operation: z.literal('role.delete'), roleId: uuid }).strict(),
  z.object({ operation: z.literal('role.assign'), roleId: uuid, userId: uuid }).strict(),
  z.object({ operation: z.literal('role.unassign'), roleId: uuid, userId: uuid }).strict(),
]);

router.get('/workspaces/:wid/roles', authMiddleware, requireWorkspaceMember('wid'), async (req: AuthRequest, res) => {
  try {
    res.json(await roleService.listRoles(req.params.wid));
  } catch (error: any) {
    if (error.message === 'ROLE_INVARIANT_EXCEEDED') {
      res.status(503).json({ error: error.message, message: 'Role invariant exceeded', statusCode: 503 });
      return;
    }
    throw error;
  }
});

router.post('/workspaces/:wid/roles', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  try {
    const body = createRoleSchema.parse(req.body);
    res.status(201).json(await roleService.createRole(req.params.wid, req.userId!, body));
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
});

router.put('/workspaces/:wid/roles/:roleId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  try {
    const roleId = uuid.parse(req.params.roleId);
    const body = updateRoleSchema.parse(req.body);
    const { expectedAuthorizationRevision, ...updates } = body;
    const result = await roleService.updateRole(
      req.params.wid,
      roleId,
      req.userId!,
      updates,
      expectedAuthorizationRevision,
    );
    await applyRealtimeEffects(req, result);
    res.json(result);
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
});

router.delete('/workspaces/:wid/roles/:roleId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  try {
    const roleId = uuid.parse(req.params.roleId);
    const body = authorizationRevisionSchema.parse(req.body);
    const result = await roleService.deleteRole(req.params.wid, roleId, req.userId!, body.expectedAuthorizationRevision);
    getIo(req)?.to(`workspace:${req.params.wid}`).emit('workspace:roles-changed', result);
    res.json(result);
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
});

router.post('/workspaces/:wid/members/:userId/roles/:roleId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  await changeAssignment(req, res, 'assign');
});

router.delete('/workspaces/:wid/members/:userId/roles/:roleId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  await changeAssignment(req, res, 'unassign');
});

router.get('/workspaces/:wid/members/:userId/permissions', authMiddleware, requireWorkspaceMembership('wid'), async (req: AuthRequest, res) => {
  try {
    const userId = uuid.parse(req.params.userId);
    if (userId !== req.userId) {
      const permissions = await getUserPermissions(req.userId!, req.params.wid);
      if ((permissions & Permissions.MANAGE_ROLES) !== Permissions.MANAGE_ROLES) {
        res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
        return;
      }
    }
    res.json(await roleService.getEffectivePermissions(req.params.wid, userId));
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
});

router.post('/workspaces/:wid/roles/preview', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_ROLES, 'wid'), async (req: AuthRequest, res) => {
  try {
    const body = previewSchema.parse(req.body);
    res.json(await roleService.previewRoleChange(req.params.wid, req.userId!, body));
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
});

async function changeAssignment(req: AuthRequest, res: Response, action: 'assign' | 'unassign') {
  try {
    const userId = uuid.parse(req.params.userId);
    const roleId = uuid.parse(req.params.roleId);
    const body = authorizationRevisionSchema.parse(req.body);
    const result = await roleService.changeRoleAssignment(
      req.params.wid,
      userId,
      roleId,
      req.userId!,
      action,
      body.expectedAuthorizationRevision,
    );
    await applyRealtimeEffects(req, result);
    res.json(result);
  } catch (error: any) {
    if (!sendRoleError(res, error)) throw error;
  }
}

async function applyRealtimeEffects(req: AuthRequest, result: {
  lostAccessUserIds: string[];
  gainedAccessUserIds: string[];
  allChannelIds: string[];
  keyedChannelIds: string[];
  roomEffects?: Array<{
    channelId: string;
    lostUserIds: string[];
    gainedUserIds: string[];
    rotationRequired: boolean;
  }>;
}) {
  const io = getIo(req);
  if (!io) return;
  for (const effect of result.roomEffects ?? []) {
    for (const userId of effect.lostUserIds) {
      io.to(`user:${userId}`).emit('channel:access-revoked', {
        workspaceId: req.params.wid,
        channelId: effect.channelId,
      });
    }
  }
  for (const userId of result.lostAccessUserIds) {
    io.to(`user:${userId}`).emit('workspace:permissions-updated', {
      workspaceId: req.params.wid,
      membershipRemoved: false,
    });
    io.in(`user:${userId}`).socketsLeave(`workspace:${req.params.wid}`);
    for (const channelId of result.allChannelIds) leaveUserChannelRooms(io, userId, channelId);
  }
  for (const userId of result.gainedAccessUserIds) {
    await joinAuthorizedUserToWorkspaceRoom(io, userId, req.params.wid);
  }
  for (const effect of result.roomEffects ?? []) {
    for (const userId of effect.lostUserIds) {
      leaveUserChannelRooms(io, userId, effect.channelId);
    }
    for (const userId of effect.gainedUserIds) {
      await joinAuthorizedUserToChannelRoom(io, userId, effect.channelId);
    }
  }
  void emitChannelKeyState(io, [
    ...result.keyedChannelIds,
    ...keyStateChannelIds(result.roomEffects ?? []),
  ]);
  io.to(`workspace:${req.params.wid}`).emit('workspace:roles-changed', { workspaceId: req.params.wid });
}

function getIo(req: AuthRequest): SocketServer | undefined {
  return req.app.get('io') as SocketServer | undefined;
}

function sendRoleError(res: Response, error: any): boolean {
  if (error?.name === 'ZodError' || ['INVALID_PERMISSIONS', 'INVALID_POSITION', 'INVALID_PREVIEW', 'INVALID_AUTHORIZATION_REVISION'].includes(error?.message)) {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid role data', statusCode: 400 });
    return true;
  }
  if (['ROLE_NOT_FOUND', 'MEMBER_NOT_FOUND', 'WORKSPACE_NOT_FOUND'].includes(error?.message)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Role or member not found', statusCode: 404 });
    return true;
  }
  if (error?.message === 'MEMBER_HIERARCHY') {
    res.status(403).json({ error: 'MEMBER_HIERARCHY', message: 'Change would reduce a higher-ranked member', statusCode: 403 });
    return true;
  }
  if (['NOT_AUTHORIZED', 'ROLE_HIERARCHY', 'PERMISSION_ESCALATION'].includes(error?.message)) {
    res.status(403).json({ error: 'FORBIDDEN', message: 'Role cannot be managed', statusCode: 403 });
    return true;
  }
  if (['OWNER_ROLE_PROTECTED', 'STANDARD_ROLE_PROTECTED', 'STANDARD_ROLE_NAME_RESERVED', 'ROLE_IN_USE', 'ROLE_NAME_EXISTS', 'ROLE_LIMIT_REACHED', 'ROLE_ASSIGNMENT_LIMIT_REACHED'].includes(error?.message) || error?.code === '23505') {
    res.status(409).json({ error: 'CONFLICT', message: 'Role change conflicts with workspace invariants', statusCode: 409 });
    return true;
  }
  if (error?.message === 'STALE_PREVIEW') {
    res.status(409).json({ error: 'STALE_PREVIEW', message: 'Role authorization preview is stale', statusCode: 409 });
    return true;
  }
  return false;
}

export default router;
