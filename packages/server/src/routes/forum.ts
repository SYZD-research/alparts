import { Router, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import {
  FORUM_POSTS_PER_PAGE,
  MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE,
  MAX_FORUM_TAG_NAME_LENGTH,
  MAX_FORUM_TAGS_PER_POST,
  MAX_PADDED_MESSAGE_BYTES,
  MESSAGES_PER_PAGE,
  Permissions,
} from '@alparts/shared';
import * as forumService from '../services/forum.service.js';
import * as messageService from '../services/message.service.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess, requireChannelPermission } from '../middleware/rbac.js';
import { displayText } from '../security/display-text.js';
import {
  broadcastForumPostUpdated,
  broadcastForumTagsUpdated,
  broadcastMessageCreated,
} from '../websocket/message.handler.js';

const router = Router();
const uuid = z.string().uuid();
const ciphertextMax = Math.ceil((MAX_PADDED_MESSAGE_BYTES + 16) / 3) * 4;
const tagIds = z.array(uuid)
  .max(MAX_FORUM_TAGS_PER_POST)
  .refine((ids) => new Set(ids).size === ids.length);
const createPostSchema = z.object({
  encryptedContent: z.string().min(24).max(ciphertextMax).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  contentNonce: z.string().length(16).regex(/^[A-Za-z0-9+/]+$/),
  broadcastMention: z.boolean(),
  mentionedUserIds: z.array(uuid)
    .max(MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE)
    .refine((ids) => new Set(ids).size === ids.length)
    .optional(),
  tagIds: tagIds.optional(),
  deviceId: uuid,
  keyVersion: z.number().int().min(1).max(1_000_000),
  idempotencyKey: uuid,
  signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
}).strict();
const listPostsSchema = z.object({
  sort: z.enum(['activity', 'created']).default('activity'),
  tagId: uuid.optional(),
  cursor: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(50).default(FORUM_POSTS_PER_PAGE),
}).strict();
const postMessagesSchema = z.object({
  cursor: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(MESSAGES_PER_PAGE),
}).strict();
const lockSchema = z.object({ locked: z.boolean() }).strict();
const resolvedSchema = z.object({ resolved: z.boolean() }).strict();
const postTagsSchema = z.object({ tagIds }).strict();
const position = z.number().int().min(0).max(1_000_000);
const createTagSchema = z.object({
  name: displayText(MAX_FORUM_TAG_NAME_LENGTH),
  position: position.optional(),
}).strict();
const updateTagSchema = z.object({
  name: displayText(MAX_FORUM_TAG_NAME_LENGTH).optional(),
  position: position.optional(),
}).strict().refine((value) => Object.keys(value).length > 0);

// === Posts ===

router.get('/channels/:id/forum/posts', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    const query = listPostsSchema.parse(req.query);
    res.json(await forumService.listForumPosts(req.params.id, req.userId!, query));
  } catch (error) {
    sendForumError(res, error);
  }
});

router.post('/channels/:id/forum/posts', authMiddleware, requireChannelPermission(Permissions.CREATE_POSTS, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = createPostSchema.parse(req.body);
    if (!req.deviceId || req.deviceId !== body.deviceId) throw new Error('DEVICE_MISMATCH');
    const result = await messageService.createMessage(req.params.id, req.userId!, {
      deviceId: body.deviceId,
      encryptedContent: body.encryptedContent,
      contentNonce: body.contentNonce,
      keyVersion: body.keyVersion,
      idempotencyKey: body.idempotencyKey,
      signature: body.signature,
      broadcastMention: body.broadcastMention,
      postId: null,
    }, undefined, body.mentionedUserIds, { tagIds: body.tagIds });
    const io = getSocketServer(req);
    if (io && result.isNewEvent) broadcastMessageCreated(io, result.event, result.attentionRecipients, result.forumPost);
    res.status(201).json({ message: result.event, state: result.forumPost });
  } catch (error) {
    sendForumError(res, error);
  }
});

router.get('/forum/posts/:postId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    res.json(await forumService.getForumPost(uuid.parse(req.params.postId), req.userId!));
  } catch (error) {
    sendForumError(res, error);
  }
});

router.get('/forum/posts/:postId/messages', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const query = postMessagesSchema.parse(req.query);
    res.json(await forumService.getForumPostMessages(uuid.parse(req.params.postId), req.userId!, query));
  } catch (error) {
    sendForumError(res, error);
  }
});

router.post('/forum/posts/:postId/read', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const read = await forumService.markForumPostRead(uuid.parse(req.params.postId), req.userId!);
    getSocketServer(req)?.to(`user:${req.userId}`).emit('forum:post-read', read);
    res.json(read);
  } catch (error) {
    sendForumError(res, error);
  }
});

router.put('/forum/posts/:postId/lock', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = lockSchema.parse(req.body);
    const result = await forumService.setForumPostLocked(uuid.parse(req.params.postId), req.userId!, body.locked);
    const io = getSocketServer(req);
    if (io && result.changed) broadcastForumPostUpdated(io, result.state);
    res.json(result.state);
  } catch (error) {
    sendForumError(res, error);
  }
});

router.put('/forum/posts/:postId/resolved', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = resolvedSchema.parse(req.body);
    const result = await forumService.setForumPostResolved(uuid.parse(req.params.postId), req.userId!, body.resolved);
    const io = getSocketServer(req);
    if (io && result.changed) broadcastForumPostUpdated(io, result.state);
    res.json(result.state);
  } catch (error) {
    sendForumError(res, error);
  }
});

router.put('/forum/posts/:postId/tags', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = postTagsSchema.parse(req.body);
    const result = await forumService.setForumPostTags(uuid.parse(req.params.postId), req.userId!, body.tagIds);
    const io = getSocketServer(req);
    if (io) broadcastForumPostUpdated(io, result.state);
    res.json(result.state);
  } catch (error) {
    sendForumError(res, error);
  }
});

// === Tags ===

router.get('/channels/:id/forum/tags', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    res.json(await forumService.listForumTags(req.params.id, req.userId!));
  } catch (error) {
    sendForumError(res, error);
  }
});

router.post('/channels/:id/forum/tags', authMiddleware, requireChannelPermission(Permissions.MANAGE_CHANNELS, 'id'), async (req: AuthRequest, res) => {
  try {
    const body = createTagSchema.parse(req.body);
    const result = await forumService.createForumTag(req.params.id, req.userId!, body.name, body.position);
    const io = getSocketServer(req);
    if (io) broadcastForumTagsUpdated(io, req.params.id, result.tags);
    res.status(201).json(result.tag);
  } catch (error) {
    sendForumError(res, error);
  }
});

router.patch('/forum/tags/:tagId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = updateTagSchema.parse(req.body);
    const result = await forumService.updateForumTag(uuid.parse(req.params.tagId), req.userId!, body);
    const io = getSocketServer(req);
    if (io) broadcastForumTagsUpdated(io, result.channelId, result.tags);
    res.json(result.tag);
  } catch (error) {
    sendForumError(res, error);
  }
});

router.delete('/forum/tags/:tagId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const result = await forumService.deleteForumTag(uuid.parse(req.params.tagId), req.userId!);
    const io = getSocketServer(req);
    if (io) broadcastForumTagsUpdated(io, result.channelId, result.tags);
    res.json({ success: true });
  } catch (error) {
    sendForumError(res, error);
  }
});

function getSocketServer(req: AuthRequest): SocketServer | undefined {
  return req.app.get('io') as SocketServer | undefined;
}

// Everything that is not visible to the caller answers 404, so post and tag
// ids cannot be used to probe channels the caller cannot see.
function sendForumError(res: Response, error: any): void {
  const code = error?.message;
  if (error?.name === 'ZodError' || code === 'INVALID_CURSOR' || code === 'INVALID_FORUM_TAGS') {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid forum request', statusCode: 400 });
    return;
  }
  if (['CHANNEL_NOT_FOUND', 'FORUM_POST_NOT_FOUND', 'FORUM_TAG_NOT_FOUND'].includes(code)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Not found', statusCode: 404 });
    return;
  }
  if (code === 'NOT_AUTHORIZED') {
    res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
    return;
  }
  if (['FORUM_TAG_EXISTS', 'FORUM_TAG_LIMIT_REACHED', 'IDEMPOTENCY_CONFLICT'].includes(code)) {
    res.status(409).json({ error: code, message: 'Conflict', statusCode: 409 });
    return;
  }
  if ([
    'DEVICE_MISMATCH',
    'INVALID_DEVICE',
    'INVALID_KEY_VERSION',
    'KEY_ROTATION_REQUIRED',
    'INVALID_SIGNATURE',
    'INVALID_REFERENCE',
    'BROADCAST_MENTION_FORBIDDEN',
  ].includes(code)) {
    res.status(400).json({ error: 'INVALID_MESSAGE', message: 'Invalid encrypted message', statusCode: 400 });
    return;
  }
  throw error;
}

export default router;
