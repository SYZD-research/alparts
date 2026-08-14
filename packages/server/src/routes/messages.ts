import { Router } from 'express';
import { z } from 'zod';
import * as messageService from '../services/message.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';
import { MESSAGES_PER_PAGE } from '@alparts/shared';

const router = Router();

const createMessageSchema = z.object({
  encryptedContent: z.string(),
  contentNonce: z.string(),
  refMessageId: z.string().uuid().optional(),
  idempotencyKey: z.string(),
  type: z.enum(['message', 'edit', 'delete', 'reaction', 'system']).optional(),
});

const editMessageSchema = z.object({
  encryptedContent: z.string(),
  contentNonce: z.string(),
});

const reactionSchema = z.object({
  emoji: z.string().min(1).max(10),
});

// Get messages for a channel
router.get('/channels/:id/messages', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const cursor = req.query.cursor as string | undefined;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : MESSAGES_PER_PAGE;
    const result = await messageService.getChannelMessages(req.params.id, { cursor, limit });
    res.json(result);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Send a message
router.post('/channels/:id/messages', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = createMessageSchema.parse(req.body);
    const message = await messageService.createMessage(
      req.params.id,
      req.userId!,
      req.body.deviceId || 'unknown',
      body.encryptedContent,
      body.contentNonce,
      body.idempotencyKey,
      body.refMessageId,
      body.type,
    );
    res.status(201).json(message);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Edit a message
router.put('/messages/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = editMessageSchema.parse(req.body);
    const message = await messageService.editMessage(
      req.params.id,
      req.userId!,
      body.encryptedContent,
      body.contentNonce,
    );
    res.json(message);
  } catch (err: any) {
    if (err.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (err.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized to edit this message', statusCode: 403 });
      return;
    }
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Delete a message
router.delete('/messages/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const result = await messageService.deleteMessage(req.params.id, req.userId!);
    res.json(result);
  } catch (err: any) {
    if (err.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Toggle reaction
router.post('/messages/:id/reactions', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = reactionSchema.parse(req.body);
    const result = await messageService.toggleReaction(req.params.id, req.userId!, body.emoji);
    res.json(result);
  } catch (err: any) {
    if (err.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Pin/unpin message
router.post('/messages/:id/pin', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { channelId } = req.body;
    if (!channelId) {
      res.status(400).json({ error: 'VALIDATION', message: 'channelId is required', statusCode: 400 });
      return;
    }
    const result = await messageService.pinMessage(req.params.id, channelId, req.userId!);
    res.json(result);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Get pinned messages
router.get('/channels/:id/pins', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const pins = await messageService.getPinnedMessages(req.params.id);
    res.json(pins);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

// Update read position
router.post('/channels/:id/read', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { messageId } = req.body;
    if (!messageId) {
      res.status(400).json({ error: 'VALIDATION', message: 'messageId is required', statusCode: 400 });
      return;
    }
    await messageService.updateReadPosition(req.userId!, req.params.id, messageId);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
