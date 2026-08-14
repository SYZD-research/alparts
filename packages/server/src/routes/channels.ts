import { Router } from 'express';
import { z } from 'zod';
import * as channelService from '../services/channel.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';
import { requirePermission } from '../middleware/rbac.js';
import { Permissions } from '@alparts/shared';

const router = Router();

const createChannelSchema = z.object({
  name: z.string().min(1).max(100),
  categoryId: z.string().uuid().optional(),
  type: z.enum(['text', 'dm', 'announcement']).optional(),
  isPrivate: z.boolean().optional(),
  topic: z.string().max(500).optional(),
  position: z.number().optional(),
});

const updateChannelSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  topic: z.string().max(500).optional(),
  categoryId: z.string().uuid().optional(),
  position: z.number().optional(),
  isPrivate: z.boolean().optional(),
});

// Get channels for a workspace
router.get('/workspaces/:wid/channels', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const channels = await channelService.getWorkspaceChannels(req.params.wid, req.userId!);
    res.json(channels);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Get categories for a workspace
router.get('/workspaces/:wid/categories', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const categories = await channelService.getWorkspaceCategories(req.params.wid);
    res.json(categories);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Create a channel
router.post('/workspaces/:wid/channels', authMiddleware, requirePermission(Permissions.MANAGE_CHANNELS), async (req: AuthRequest, res) => {
  try {
    const body = createChannelSchema.parse(req.body);
    const channel = await channelService.createChannel(req.params.wid, body.name, body.type, {
      categoryId: body.categoryId,
      isPrivate: body.isPrivate,
      topic: body.topic,
      position: body.position,
    });
    res.status(201).json(channel);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Get channel details
router.get('/channels/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const channel = await channelService.getChannelById(req.params.id);
    if (!channel) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    res.json(channel);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Update channel
router.put('/channels/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = updateChannelSchema.parse(req.body);
    const channel = await channelService.updateChannel(req.params.id, body);
    if (!channel) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    res.json(channel);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Delete channel
router.delete('/channels/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    await channelService.deleteChannel(req.params.id);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Get channel members
router.get('/channels/:id/members', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const members = await channelService.getChannelMembers(req.params.id);
    res.json(members);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Create category
router.post('/workspaces/:wid/categories', authMiddleware, requirePermission(Permissions.MANAGE_CHANNELS), async (req: AuthRequest, res) => {
  try {
    const { name, position } = req.body;
    if (!name) {
      res.status(400).json({ error: 'VALIDATION', message: 'name is required', statusCode: 400 });
      return;
    }
    const category = await channelService.createCategory(req.params.wid, name, position);
    res.status(201).json(category);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
