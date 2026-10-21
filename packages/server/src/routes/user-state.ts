import { Router } from 'express';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess, requireWorkspaceMembership } from '../middleware/rbac.js';
import * as userStateService from '../services/user-state.service.js';
import { rateLimit, requestSource } from '../middleware/rate-limit.js';
import { canonicalUuid } from '../security/canonical-id.js';

const router = Router();
const messageId = canonicalUuid;
const preferenceSchema = z.object({
  favorite: z.boolean().optional(),
  muted: z.boolean().optional(),
  hidden: z.boolean().optional(),
  notificationLevel: z.enum(['all', 'mentions', 'none']).optional(),
}).strict().refine((value) => Object.keys(value).length > 0);
const bookmarkQuery = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
}).strict();
const channelStateLimit = rateLimit({
  windowMs: 60_000,
  max: 30,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});

router.get('/workspaces/:wid/channel-state', authMiddleware, channelStateLimit, requireWorkspaceMembership('wid'), async (req: AuthRequest, res) => {
  res.json(await userStateService.getWorkspaceChannelState(req.params.wid, req.userId!));
});

router.patch('/channels/:id/preferences', authMiddleware, requireChannelAccess('id'), async (req: AuthRequest, res) => {
  try {
    const body = preferenceSchema.parse(req.body);
    res.json(await userStateService.updateChannelPreference(req.params.id, req.userId!, body));
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid channel preference', statusCode: 400 });
      return;
    }
    if (error.message === 'CHANNEL_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Channel not found', statusCode: 404 });
      return;
    }
    throw error;
  }
});

// The service checks the channel itself: a member who lost it may still
// remove a bookmark they made there.
router.post('/messages/:id/bookmark', authMiddleware, async (req: AuthRequest, res) => {
  if (!messageId.safeParse(req.params.id).success) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
    return;
  }
  try {
    res.json(await userStateService.toggleMessageBookmark(req.params.id, req.userId!));
  } catch (error: any) {
    if (error.message === 'MESSAGE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Message not found', statusCode: 404 });
      return;
    }
    if (error.message === 'BOOKMARK_LIMIT_REACHED') {
      res.status(409).json({ error: error.message, message: 'Bookmark quota reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

router.get('/bookmarks', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const query = bookmarkQuery.parse(req.query);
    res.json(await userStateService.listMessageBookmarks(req.userId!, query.limit));
  } catch (error: any) {
    if (error.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid bookmark query', statusCode: 400 });
      return;
    }
    throw error;
  }
});

export default router;
