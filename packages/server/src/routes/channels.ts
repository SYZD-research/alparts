import { displayText } from '../security/display-text.js';
import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { Permissions } from '@alparts/shared';
import * as channelService from '../services/channel.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import {
  requireChannelAccess,
  requireChannelPermission,
  requireWorkspaceMembership,
  requireWorkspacePermission,
} from '../middleware/rbac.js';
import {
  clearDeletedChannelRooms,
  joinAuthorizedUserToChannelRoom,
  leaveUserChannelRooms,
} from '../websocket/room-membership.js';

const router = Router();
const position = z.number().int().min(0).max(1_000_000);
const createChannelSchema = z.object({
  name: displayText(),
  categoryId: z.string().uuid().optional(),
  type: z.enum(['text', 'announcement', 'voice']).optional(),
  isPrivate: z.boolean().optional(),
  topic: displayText(500, true).optional(),
  position: position.optional(),
}).strict();
const updateChannelSchema = z.object({
  name: displayText().optional(),
  topic: displayText(500, true).optional(),
  categoryId: z.string().uuid().nullable().optional(),
  position: position.optional(),
  isPrivate: z.boolean().optional(),
}).strict().refine((value) => Object.keys(value).length > 0);
const createCategorySchema = z.object({
  name: displayText(),
  position: position.optional(),
}).strict();
const updateCategorySchema = z.object({
  name: displayText().optional(),
  position: position.optional(),
}).strict().refine((value) => Object.keys(value).length > 0);
const channelMemberSchema = z.object({ userId: z.string().uuid() }).strict();

router.get('/workspaces/:wid/channels', authMiddleware, requireWorkspaceMembership('wid'), async (req: AuthRequest, res) => {
  res.json(await channelService.getWorkspaceChannels(req.params.wid, req.userId!));
});

router.get('/workspaces/:wid/categories', authMiddleware, requireWorkspaceMembership('wid'), async (req: AuthRequest, res) => {
  res.json(await channelService.getWorkspaceCategories(req.params.wid, req.userId!));
});

router.post('/workspaces/:wid/channels', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'), async (req: AuthRequest, res) => {
  try {
    const body = createChannelSchema.parse(req.body);
    const channel = await channelService.createChannel(req.params.wid, body.name, body.type, {
      categoryId: body.categoryId,
      isPrivate: body.isPrivate,
      topic: body.topic,
      position: body.position,
    }, req.userId!);
    res.status(201).json(channel);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'INVALID_CATEGORY') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid channel data', statusCode: 400 });
      return;
    }
    if (error.message === 'WORKSPACE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
      return;
    }
    if (error.message === 'CHANNEL_LIMIT_REACHED') {
      res.status(409).json({ error: 'CHANNEL_LIMIT_REACHED', message: 'Workspace channel limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/channels/:id', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  const channel = await channelService.getChannelById(req.params.id);
  if (!channel) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
    return;
  }
  res.json(channel);
});

router.put('/channels/:id', authMiddleware, requireChannelPermission(Permissions.MANAGE_CHANNELS, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = updateChannelSchema.parse(req.body);
    const result = await channelService.updateChannel(req.params.id, body, req.userId!);
    if (!result) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    const io = req.app.get('io') as SocketServer | undefined;
    for (const userId of result.removedUserIds) {
      io?.to(`user:${userId}`).emit('channel:access-revoked', {
        workspaceId: result.workspaceId,
        channelId: req.params.id,
      });
      if (io) leaveUserChannelRooms(io, userId, req.params.id);
    }
    if (io) {
      for (const userId of result.gainedUserIds) {
        await joinAuthorizedUserToChannelRoom(io, userId, req.params.id);
      }
    }
    if (result.rotationRequired) {
      io?.to(`channel:${req.params.id}`).emit('channel:key-rotation-required', { channelId: req.params.id });
    }
    io?.to(`channel:${req.params.id}`).emit('channel:updated', result.channel);
    res.json(result.channel);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'INVALID_CATEGORY') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid channel data', statusCode: 400 });
      return;
    }
    if (error.message === 'CHANNEL_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    throw error;
  }
});

router.delete('/channels/:id', authMiddleware, requireChannelPermission(Permissions.MANAGE_CHANNELS, 'id'), async (req: AuthRequest, res) => {
  try {
    const result = await channelService.deleteChannel(req.params.id, req.userId!);
    if (!result) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    const io = req.app.get('io') as SocketServer | undefined;
    // Notify every formerly authorized viewer through its identity room. A
    // client may have persisted state for an inactive channel without being
    // joined to the channel room at deletion time.
    for (const userId of result.viewerUserIds) {
      io?.to(`user:${userId}`).emit('channel:deleted', {
        channelId: result.channelId,
        workspaceId: result.workspaceId,
      });
    }
    if (io) clearDeletedChannelRooms(io, req.params.id);
    res.json({ success: true });
  } catch (error: any) {
    if (error.message === 'CHANNEL_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    if (error.message === 'CHANNEL_IN_USE') {
      res.status(409).json({ error: 'CONFLICT', message: 'Channel has dependent data', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/channels/:id/members', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  res.json(await channelService.getChannelMembers(req.params.id));
});

router.post('/channels/:id/members', authMiddleware, requireChannelPermission(Permissions.MANAGE_CHANNELS, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = channelMemberSchema.parse(req.body);
    const member = await channelService.addChannelMember(req.params.id, body.userId, req.userId!);
    const io = req.app.get('io') as SocketServer | undefined;
    if (io) {
      for (const effect of member.roomEffects) {
        for (const gainedUserId of effect.gainedUserIds) {
          await joinAuthorizedUserToChannelRoom(io, gainedUserId, effect.channelId);
        }
      }
    }
    io?.to(`channel:${req.params.id}`).emit('channel:member-added', member);
    res.status(201).json(member);
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid channel member', statusCode: 400 });
      return;
    }
    if (['CHANNEL_NOT_FOUND', 'PRIVATE_CHANNEL_NOT_FOUND', 'WORKSPACE_MEMBER_REQUIRED'].includes(error.message)) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Eligible private channel member not found', statusCode: 404 });
      return;
    }
    throw error;
  }
});

router.delete('/channels/:id/members/:userId', authMiddleware, requireChannelPermission(Permissions.MANAGE_CHANNELS, 'id'), async (req: AuthRequest, res) => {
  if (!z.string().uuid().safeParse(req.params.userId).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Channel member not found', statusCode: 404 });
    return;
  }
  try {
    const result = await channelService.removeChannelMember(req.params.id, req.params.userId, req.userId!);
    const io = req.app.get('io') as SocketServer | undefined;
    for (const effect of result.roomEffects) {
      for (const lostUserId of effect.lostUserIds) {
        io?.to(`user:${lostUserId}`).emit('channel:access-revoked', {
          workspaceId: result.workspaceId,
          channelId: effect.channelId,
        });
        if (io) leaveUserChannelRooms(io, lostUserId, effect.channelId);
      }
    }
    io?.to(`channel:${req.params.id}`).emit('channel:member-removed', result);
    if (result.rotationRequired) {
      io?.to(`channel:${req.params.id}`).emit('channel:key-rotation-required', { channelId: req.params.id });
    }
    res.json({ success: true });
  } catch (error: any) {
    if (['CHANNEL_NOT_FOUND', 'PRIVATE_CHANNEL_NOT_FOUND', 'CHANNEL_MEMBER_NOT_FOUND'].includes(error.message)) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel member not found', statusCode: 404 });
      return;
    }
    if (error.message === 'LAST_PRIVATE_MEMBER') {
      res.status(409).json({ error: 'LAST_PRIVATE_MEMBER', message: 'A private channel must retain an explicit member', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.post('/workspaces/:wid/categories', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'), async (req: AuthRequest, res) => {
  try {
    const body = createCategorySchema.parse(req.body);
    const category = await channelService.createCategory(req.params.wid, body.name, body.position, req.userId!);
    res.status(201).json(category);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'INVALID_POSITION') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid category data', statusCode: 400 });
      return;
    }
    if (error.message === 'WORKSPACE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Workspace not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
      return;
    }
    if (error.message === 'CATEGORY_LIMIT_REACHED') {
      res.status(409).json({ error: 'CATEGORY_LIMIT_REACHED', message: 'Workspace category limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.put('/workspaces/:wid/categories/:categoryId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'), async (req: AuthRequest, res) => {
  try {
    const categoryId = z.string().uuid().parse(req.params.categoryId);
    const body = updateCategorySchema.parse(req.body);
    const category = await channelService.updateCategory(req.params.wid, categoryId, body, req.userId!);
    if (!category) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Category not found', statusCode: 404 });
      return;
    }
    res.json(category);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'INVALID_POSITION') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid category data', statusCode: 400 });
      return;
    }
    if (['CATEGORY_NOT_FOUND', 'WORKSPACE_NOT_FOUND'].includes(error.message)) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Category not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
      return;
    }
    throw error;
  }
});

router.delete('/workspaces/:wid/categories/:categoryId', authMiddleware, requireWorkspacePermission(Permissions.MANAGE_CHANNELS, 'wid'), async (req: AuthRequest, res) => {
  if (!z.string().uuid().safeParse(req.params.categoryId).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Category not found', statusCode: 404 });
    return;
  }
  try {
    const result = await channelService.deleteCategory(req.params.wid, req.params.categoryId, req.userId!);
    const io = req.app.get('io') as SocketServer | undefined;
    for (const effect of result.roomEffects) {
      for (const userId of effect.lostUserIds) {
        io?.to(`user:${userId}`).emit('channel:access-revoked', {
          workspaceId: result.workspaceId,
          channelId: effect.channelId,
        });
        if (io) leaveUserChannelRooms(io, userId, effect.channelId);
      }
      if (io) {
        for (const userId of effect.gainedUserIds) {
          await joinAuthorizedUserToChannelRoom(io, userId, effect.channelId);
        }
      }
      if (effect.rotationRequired) {
        io?.to(`channel:${effect.channelId}`).emit('channel:key-rotation-required', { channelId: effect.channelId });
      }
      io?.to(`channel:${effect.channelId}`).emit('channel:permissions-updated', {
        channelId: effect.channelId,
        workspaceId: result.workspaceId,
      });
    }
    res.json(result);
  } catch (error: any) {
    if (['CATEGORY_NOT_FOUND', 'WORKSPACE_NOT_FOUND'].includes(error.message)) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Category not found', statusCode: 404 });
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
