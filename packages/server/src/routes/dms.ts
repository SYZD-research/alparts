import { Router } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireWorkspaceMember, requireWorkspaceMembership } from '../middleware/rbac.js';
import * as dmService from '../services/dm.service.js';
import { joinAuthorizedUserToChannelRoom } from '../websocket/room-membership.js';

const router = Router();
const createSchema = z.object({
  memberIds: z.array(z.string().uuid()).min(1).max(19),
}).strict();

router.get('/workspaces/:wid/dms', authMiddleware, requireWorkspaceMembership('wid'), async (req: AuthRequest, res) => {
  res.json(await dmService.listDms(req.params.wid, req.userId!));
});

router.post('/workspaces/:wid/dms', authMiddleware, requireWorkspaceMember('wid'), async (req: AuthRequest, res) => {
  try {
    const body = createSchema.parse(req.body);
    const dm = await dmService.createDm(req.params.wid, req.userId!, body.memberIds);
    const io = req.app.get('io') as SocketServer | undefined;
    for (const member of dm.members) {
      if (io) await joinAuthorizedUserToChannelRoom(io, member.id, dm.channelId);
      io?.to(`user:${member.id}`).emit('dm:created', { dm });
    }
    res.status(201).json(dm);
  } catch (error: any) {
    if (error.name === 'ZodError' || error.message === 'DM_REQUIRES_RECIPIENT') {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid direct-message members', statusCode: 400 });
      return;
    }
    if (error.message === 'DM_MEMBER_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Direct-message member not found', statusCode: 404 });
      return;
    }
    if (['DM_WORKSPACE_LIMIT_REACHED', 'DM_USER_LIMIT_REACHED'].includes(error.message)) {
      res.status(409).json({ error: error.message, message: 'Direct-message quota reached', statusCode: 409 });
      return;
    }
    throw error;
  }
});

export default router;
