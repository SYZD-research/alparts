import { randomUUID } from 'node:crypto';
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import type { WsAttentionNotification } from '@alparts/shared';
import { z } from 'zod';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireWorkspaceMembership } from '../middleware/rbac.js';
import { rateLimit, requestSource } from '../middleware/rate-limit.js';
import { reserveKnownLengthBody } from '../middleware/body-admission.js';
import { displayText } from '../security/display-text.js';
import { MAX_AVATAR_BYTES, profileBio } from '../security/profile-input.js';
import { logError } from '../security/logger.js';
import { acquireAvatarDownloadLease } from '../security/download-limits.js';
import * as profileService from '../services/profile.service.js';

const router = Router();
const uuid = z.string().uuid();
const perUser = (max: number) => rateLimit({
  windowMs: 60 * 60 * 1000,
  max,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const profileLimit = perUser(30);
const avatarLimit = perUser(10);
const flagLimit = perUser(60);
const profileSchema = z.object({
  displayName: displayText().optional(),
  bio: profileBio().optional(),
}).strict().refine((value) => value.displayName !== undefined || value.bio !== undefined);

const rawAvatarParser = express.raw({ type: 'image/png', limit: MAX_AVATAR_BYTES });
const parseAvatarBody = (req: Request, res: Response, next: NextFunction) => {
  if (!req.is('image/png')) {
    res.status(415).json({ error: 'UNSUPPORTED_MEDIA_TYPE', message: 'Avatar must be image/png', statusCode: 415 });
    return;
  }
  rawAvatarParser(req, res, (error?: any) => {
    if (error?.type === 'entity.too.large' || error?.status === 413) {
      res.status(413).json({ error: 'AVATAR_TOO_LARGE', message: 'Avatar is too large', statusCode: 413 });
      return;
    }
    next(error);
  });
};

function io(req: Request): SocketServer | undefined {
  return req.app.get('io') as SocketServer | undefined;
}

async function announceProfileChange(req: Request, userId: string) {
  try {
    for (const workspaceId of await profileService.workspaceIdsOf(userId)) {
      io(req)?.to(`workspace:${workspaceId}`).emit('member:profile-updated', { workspaceId, userId });
    }
  } catch (error) {
    logError('profile.announce', error);
  }
}

function sendProfileError(res: Response, error: any): boolean {
  if (error?.name === 'ZodError' || error?.message === 'INVALID_AVATAR') {
    res.status(400).json({ error: error?.message === 'INVALID_AVATAR' ? 'INVALID_AVATAR' : 'VALIDATION', message: 'Invalid profile data', statusCode: 400 });
    return true;
  }
  if (['MEMBER_NOT_FOUND', 'USER_NOT_FOUND', 'WORKSPACE_NOT_FOUND', 'PROFILE_FLAG_NOT_FOUND'].includes(error?.message)) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Profile not found', statusCode: 404 });
    return true;
  }
  if (error?.message === 'NOT_AUTHORIZED' || error?.message === 'MEMBER_HIERARCHY') {
    res.status(403).json({ error: error.message === 'MEMBER_HIERARCHY' ? 'MEMBER_HIERARCHY' : 'FORBIDDEN', message: 'Not allowed', statusCode: 403 });
    return true;
  }
  if (['PROFILE_APPEAL_USED', 'PROFILE_APPEAL_NEEDS_CHANGE', 'PROFILE_APPEAL_NOT_PENDING'].includes(error?.message)) {
    res.status(409).json({ error: error.message, message: 'Request not possible', statusCode: 409 });
    return true;
  }
  return false;
}

const handle = (operation: (req: AuthRequest, res: Response) => Promise<void>) =>
  async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      await operation(req, res);
    } catch (error) {
      if (!sendProfileError(res, error)) next(error);
    }
  };

// Own profile
router.get('/profile', authMiddleware, handle(async (req, res) => {
  res.json(await profileService.getOwnProfile(req.userId!));
}));

router.patch('/profile', authMiddleware, profileLimit, handle(async (req, res) => {
  const body = profileSchema.parse(req.body);
  await profileService.updateProfile(req.userId!, body);
  await announceProfileChange(req, req.userId!);
  res.json(await profileService.getOwnProfile(req.userId!));
}));

router.put('/profile/avatar', authMiddleware, avatarLimit, reserveKnownLengthBody(MAX_AVATAR_BYTES), parseAvatarBody,
  handle(async (req, res) => {
    if (!Buffer.isBuffer(req.body)) throw new Error('INVALID_AVATAR');
    const result = await profileService.setAvatar(req.userId!, req.body);
    await announceProfileChange(req, req.userId!);
    res.json(result);
  }));

router.delete('/profile/avatar', authMiddleware, avatarLimit, handle(async (req, res) => {
  await profileService.removeAvatar(req.userId!);
  await announceProfileChange(req, req.userId!);
  res.json({ success: true });
}));

router.get('/users/:userId/avatar/:version', authMiddleware, handle(async (req, res) => {
  const userId = uuid.parse(req.params.userId);
  const version = uuid.parse(req.params.version);
  const release = acquireAvatarDownloadLease(req.userId!);
  if (!release) {
    res.status(429).json({ error: 'DOWNLOAD_LIMIT_REACHED', message: 'Too many concurrent downloads', statusCode: 429 });
    return;
  }
  res.once('close', release);
  const image = await profileService.readAvatar(req.userId!, userId, version);
  if (!image) {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Profile not found', statusCode: 404 });
    return;
  }
  // The URL changes with every new image, so the bytes behind it never change.
  res.setHeader('Cache-Control', 'private, max-age=86400, immutable');
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.end(image);
}));

// Workspace-scoped profile view and warnings
router.get('/workspaces/:wid/members/:userId/profile', authMiddleware, requireWorkspaceMembership('wid'),
  handle(async (req, res) => {
    res.json(await profileService.getMemberProfile(req.params.wid, req.userId!, uuid.parse(req.params.userId)));
  }));

router.get('/workspaces/:wid/profile-flags', authMiddleware, requireWorkspaceMembership('wid'), handle(async (req, res) => {
  res.json(await profileService.listProfileFlags(req.params.wid, req.userId!));
}));

router.get('/workspaces/:wid/warned-users', authMiddleware, requireWorkspaceMembership('wid'), handle(async (req, res) => {
  res.json(await profileService.listWarnedUserIds(req.params.wid));
}));

function announceFlags(req: Request, workspaceId: string) {
  io(req)?.to(`workspace:${workspaceId}`).emit('workspace:profile-flags-changed', { workspaceId });
}

router.put('/workspaces/:wid/members/:userId/profile-flag', authMiddleware, requireWorkspaceMembership('wid'), flagLimit,
  handle(async (req, res) => {
    await profileService.flagProfile(req.params.wid, req.userId!, uuid.parse(req.params.userId));
    announceFlags(req, req.params.wid);
    res.json({ success: true });
  }));

router.delete('/workspaces/:wid/members/:userId/profile-flag', authMiddleware, requireWorkspaceMembership('wid'), flagLimit,
  handle(async (req, res) => {
    await profileService.unflagProfile(req.params.wid, req.userId!, uuid.parse(req.params.userId));
    announceFlags(req, req.params.wid);
    res.json({ success: true });
  }));

router.post('/workspaces/:wid/members/:userId/profile-flag/deny', authMiddleware, requireWorkspaceMembership('wid'), flagLimit,
  handle(async (req, res) => {
    await profileService.denyProfileAppeal(req.params.wid, req.userId!, uuid.parse(req.params.userId));
    announceFlags(req, req.params.wid);
    res.json({ success: true });
  }));

router.post('/workspaces/:wid/profile-flag/appeal', authMiddleware, requireWorkspaceMembership('wid'), flagLimit,
  handle(async (req, res) => {
    const managers = await profileService.requestProfileAppeal(req.params.wid, req.userId!);
    announceFlags(req, req.params.wid);
    for (const managerId of managers) {
      io(req)?.to(`user:${managerId}`).emit('attention:new', {
        notificationId: randomUUID(),
        workspaceId: req.params.wid,
        channelId: null,
        kind: 'profile-appeal',
      } satisfies WsAttentionNotification);
    }
    res.json({ success: true });
  }));

export default router;
