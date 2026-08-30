import type { NextFunction, Response } from 'express';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import type { AuthRequest } from './auth.js';
import { db } from '../db/index.js';
import { messages, workspaceMembers } from '../db/schema.js';
import {
  getChannelAuthorization as getCentralChannelAuthorization,
  getWorkspaceAuthorization,
  type ChannelAuthorization,
} from '../services/authorization.service.js';
import { setLogTenant } from '../security/log-context.js';

const uuid = z.string().uuid();

export async function getUserPermissions(userId: string, workspaceId: string): Promise<number> {
  return (await getWorkspaceAuthorization(workspaceId, userId))?.permissionMask ?? 0;
}

export async function getChannelAuthorization(userId: string, channelId: string): Promise<ChannelAuthorization | null> {
  return getCentralChannelAuthorization(userId, channelId);
}

export async function canAccessChannel(userId: string, channelId: string): Promise<boolean> {
  return Boolean(await getChannelAuthorization(userId, channelId));
}

export function requireWorkspacePermission(permission: number, parameter = 'wid') {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const workspaceId = req.params[parameter];
    if (!req.userId || !uuid.safeParse(workspaceId).success) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
      return;
    }
    try {
      setLogTenant(workspaceId);
      const permissions = await getUserPermissions(req.userId, workspaceId);
      if ((permissions & permission) !== permission) {
        res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireWorkspaceMember(parameter = 'id') {
  return requireWorkspacePermission(Permissions.VIEW_CHANNELS, parameter);
}

export function requireWorkspaceMembership(parameter = 'wid') {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const workspaceId = req.params[parameter];
    if (!req.userId || !uuid.safeParse(workspaceId).success) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
      return;
    }
    try {
      setLogTenant(workspaceId);
      const membership = await db.query.workspaceMembers.findFirst({
        columns: { id: true },
        where: and(
          eq(workspaceMembers.workspaceId, workspaceId),
          eq(workspaceMembers.userId, req.userId),
        ),
      });
      if (!membership) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireChannelPermission(permission: number, parameter = 'id') {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const channelId = req.params[parameter];
    if (!req.userId || !uuid.safeParse(channelId).success) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    try {
      const authorization = await getChannelAuthorization(req.userId, channelId);
      if (!authorization) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
        return;
      }
      setLogTenant(authorization.workspaceId);
      if ((authorization.permissions & permission) !== permission) {
        res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireChannelAccess(parameter = 'id') {
  return requireChannelPermission(Permissions.VIEW_CHANNELS, parameter);
}

export function requireMessagePermission(permission: number, parameter = 'id') {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const messageId = req.params[parameter];
    if (!req.userId || !uuid.safeParse(messageId).success) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    try {
      const message = await db.query.messages.findFirst({
        columns: { channelId: true },
        where: eq(messages.id, messageId),
      });
      if (!message) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
        return;
      }
      const authorization = await getChannelAuthorization(req.userId, message.channelId);
      if (!authorization) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
        return;
      }
      setLogTenant(authorization.workspaceId);
      if ((authorization.permissions & permission) !== permission) {
        res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Kept as a safe compatibility wrapper: missing route parameters now fail closed.
export function requirePermission(permission: number, parameter = 'wid') {
  return requireWorkspacePermission(permission, parameter);
}
