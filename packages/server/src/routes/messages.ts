import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { MAX_MESSAGE_LENGTH, MESSAGES_PER_PAGE, Permissions } from '@alparts/shared';
import * as messageService from '../services/message.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess, requireChannelPermission, requireMessagePermission } from '../middleware/rbac.js';
import {
  broadcastMessageCreated,
  broadcastMessageDeleted,
  broadcastMessageEdited,
  broadcastPinUpdated,
  broadcastReactionUpdated,
} from '../websocket/message.handler.js';

const router = Router();
const ciphertextMax = Math.ceil((MAX_MESSAGE_LENGTH * 4 + 16) / 3) * 4;
const encryptedContent = z.string().min(24).max(ciphertextMax).regex(/^[A-Za-z0-9+/]+={0,2}$/);
const nonce = z.string().length(16).regex(/^[A-Za-z0-9+/]+$/);
const signature = z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/);
const cryptoFields = {
  deviceId: z.string().uuid(),
  keyVersion: z.number().int().min(1).max(1_000_000),
  idempotencyKey: z.string().uuid(),
  signature,
};
const createMessageSchema = z.object({
  encryptedContent,
  contentNonce: nonce,
  refMessageId: z.string().uuid().optional(),
  broadcastMention: z.boolean(),
  ...cryptoFields,
}).strict();
const editMessageSchema = z.object({
  encryptedContent,
  contentNonce: nonce,
  broadcastMention: z.boolean(),
  ...cryptoFields,
}).strict();
const deleteMessageSchema = z.object(cryptoFields).strict();
const reactionSchema = z.object({ emoji: z.string().min(1).max(10) }).strict();
const readSchema = z.object({ messageId: z.string().uuid() }).strict();
const paginationSchema = z.object({
  cursor: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(MESSAGES_PER_PAGE),
}).strict();

router.get('/channels/:id/messages', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    const query = paginationSchema.parse(req.query);
    res.json(await messageService.getChannelMessages(req.params.id, query));
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'INVALID_CURSOR') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid pagination cursor', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.post('/channels/:id/messages', authMiddleware, requireChannelPermission(Permissions.SEND_MESSAGES, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = createMessageSchema.parse(req.body);
    assertBoundDevice(req, body.deviceId);
    const result = await messageService.createMessage(req.params.id, req.userId!, {
      deviceId: body.deviceId,
      encryptedContent: body.encryptedContent,
      contentNonce: body.contentNonce,
      keyVersion: body.keyVersion,
      idempotencyKey: body.idempotencyKey,
      signature: body.signature,
      broadcastMention: body.broadcastMention,
    }, body.refMessageId);
    const io = getSocketServer(req);
    if (io && result.isNewEvent) broadcastMessageCreated(io, result.event);
    res.status(201).json(result.event);
  } catch (error: any) {
    if (error.message === 'IDEMPOTENCY_CONFLICT') {
      res.status(409).json({ error: 'IDEMPOTENCY_CONFLICT', message: 'Idempotency key was already used', statusCode: 409 });
      return;
    }
    if (isInvalidCryptoRequest(error)) {
      res.status(400).json({ error: 'INVALID_MESSAGE', message: 'Invalid encrypted message', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.put('/messages/:id', authMiddleware, requireMessagePermission(Permissions.EDIT_MESSAGES, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = editMessageSchema.parse(req.body);
    assertBoundDevice(req, body.deviceId);
    const result = await messageService.editMessage(req.params.id, req.userId!, body);
    const io = getSocketServer(req);
    if (io && result.isNewEvent) broadcastMessageEdited(io, result.event);
    res.json(result.event);
  } catch (error: any) {
    if (error.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized to edit this message', statusCode: 403 });
      return;
    }
    if (error.message === 'IDEMPOTENCY_CONFLICT') {
      res.status(409).json({ error: 'IDEMPOTENCY_CONFLICT', message: 'Idempotency key was already used', statusCode: 409 });
      return;
    }
    if (isInvalidCryptoRequest(error)) {
      res.status(400).json({ error: 'INVALID_MESSAGE', message: 'Invalid encrypted message', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.delete('/messages/:id', authMiddleware, requireMessagePermission(Permissions.DELETE_MESSAGES, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = deleteMessageSchema.parse(req.body);
    assertBoundDevice(req, body.deviceId);
    const result = await messageService.deleteMessage(req.params.id, req.userId!, {
      ...body,
      encryptedContent: '',
      contentNonce: '',
      broadcastMention: false,
    });
    const payload = { messageId: result.messageId, channelId: result.channelId, event: result.event };
    const io = getSocketServer(req);
    if (io && result.isNewEvent) broadcastMessageDeleted(io, payload);
    res.json(payload);
  } catch (error: any) {
    if (error.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized to delete this message', statusCode: 403 });
      return;
    }
    if (error.message === 'IDEMPOTENCY_CONFLICT') {
      res.status(409).json({ error: 'IDEMPOTENCY_CONFLICT', message: 'Idempotency key was already used', statusCode: 409 });
      return;
    }
    if (isInvalidCryptoRequest(error)) {
      res.status(400).json({ error: 'INVALID_MESSAGE', message: 'Invalid signed deletion', statusCode: 400 });
      return;
    }
    throw error;
  }
});

router.post('/messages/:id/reactions', authMiddleware, requireMessagePermission(Permissions.ADD_REACTIONS, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = reactionSchema.parse(req.body);
    const result = await messageService.toggleReaction(req.params.id, req.userId!, body.emoji);
    const io = getSocketServer(req);
    if (io) broadcastReactionUpdated(io, result);
    res.json(result);
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid reaction', statusCode: 400 });
      return;
    }
    if (error.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized to react', statusCode: 403 });
      return;
    }
    if (error.message === 'REACTION_LIMIT_REACHED') {
      res.status(409).json({ error: 'REACTION_LIMIT_REACHED', message: 'Reaction limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.post('/messages/:id/pin', authMiddleware, requireMessagePermission(Permissions.PIN_MESSAGES, 'id'), async (req: AuthRequest, res) => {
  try {
    const result = await messageService.pinMessage(req.params.id, req.userId!);
    const io = getSocketServer(req);
    if (io) broadcastPinUpdated(io, result);
    res.json(result);
  } catch (error: any) {
    if (error.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (error.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized to pin', statusCode: 403 });
      return;
    }
    if (error.message === 'PIN_LIMIT_REACHED') {
      res.status(409).json({ error: 'PIN_LIMIT_REACHED', message: 'Channel pin limit reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/channels/:id/pins', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  res.json(await messageService.getPinnedMessages(req.params.id));
});

router.post('/channels/:id/read', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    const body = readSchema.parse(req.body);
    const position = await messageService.updateReadPosition(req.userId!, req.params.id, body.messageId);
    getSocketServer(req)?.to(`user:${req.userId}`).emit('read:updated', position);
    res.json(position);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'MESSAGE_NOT_FOUND') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid read position', statusCode: 400 });
      return;
    }
    throw error;
  }
});

function assertBoundDevice(req: AuthRequest, deviceId: string): void {
  if (!req.deviceId || req.deviceId !== deviceId) throw new Error('DEVICE_MISMATCH');
}

function getSocketServer(req: AuthRequest): SocketServer | undefined {
  return req.app.get('io') as SocketServer | undefined;
}

function isInvalidCryptoRequest(error: any): boolean {
  return error?.name === 'ZodError' || [
    'DEVICE_MISMATCH',
    'INVALID_DEVICE',
    'INVALID_KEY_VERSION',
    'KEY_ROTATION_REQUIRED',
    'INVALID_SIGNATURE',
    'INVALID_REFERENCE',
    'BROADCAST_MENTION_FORBIDDEN',
  ].includes(error?.message);
}

export default router;
