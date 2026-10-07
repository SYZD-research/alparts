import { randomUUID } from 'node:crypto';
import { Router, type NextFunction, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import type { WsAttentionNotification } from '@alparts/shared';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { requireChannelAccess } from '../middleware/rbac.js';
import { rateLimit } from '../middleware/rate-limit.js';
import * as service from '../services/mls-group.service.js';
import { emitChannelKeyState } from '../websocket/key-state.js';
import {
  mlsGroupCommitRequest,
  mlsGroupCommitsQuery,
  mlsGroupFreshStartRequest,
  mlsGroupMembersQuery,
  mlsGroupPendingQuery,
  mlsMemberPackageRequest,
} from './mls-schema.js';

const router = Router();
const deviceKey = (req: AuthRequest) => req.deviceId || req.userId!;
// Per device, so migration work of several devices of one account does not
// share one budget; commits are also per channel.
const readLimit = rateLimit({ windowMs: 60_000, max: 600, key: (req) => deviceKey(req as AuthRequest) });
const packageLimit = rateLimit({ windowMs: 60_000, max: 120, key: (req) => deviceKey(req as AuthRequest) });
const commitLimit = rateLimit({
  windowMs: 60_000,
  max: 60,
  key: (req) => `${deviceKey(req as AuthRequest)}:${req.params.id || 'unknown'}`,
});

// 409: depends on state the client may have read earlier; re-read and retry.
const CONFLICT_CODES = new Set([
  'MLS_CONFLICT',
  'GENESIS_WAITING',
  'KEY_ROTATION_NOT_REQUIRED',
  'COMMIT_RATE_LIMITED',
  'PACKAGE_KEY_CONFLICT',
  'PACKAGE_CONSUMED',
  'ALREADY_MEMBER',
  'REJOIN_LIMIT',
  'KEY_FRESH_START_NOT_REQUIRED',
  'KEY_RECIPIENT_LIMIT',
]);
// 403: invalid in every state, or not permitted for this device (including
// a failed identity confirmation for fresh start).
const FORBIDDEN_CODES = new Set([
  'INVALID_MLS',
  'KEY_FRESH_START_REQUIRED',
  'INVALID_KEY_FRESH_START',
  'DEVICE_APPROVAL_REQUIRED',
  'DEVICE_REQUIRED',
  'AUTHENTICATION_FAILED',
  'AUTHENTICATION_LIMIT',
  'PASSKEY_REQUIRED',
  'INVALID_CREDENTIALS',
]);

const handle =
  (fn: (req: AuthRequest, res: Response) => Promise<void>) =>
  async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.deviceId) {
        res.sendStatus(403);
        return;
      }
      await fn(req, res);
    } catch (error: any) {
      const code = error instanceof Error ? error.message : '';
      if (error?.name === 'ZodError') {
        res.status(400).json({ error: 'VALIDATION', message: 'Invalid request', statusCode: 400 });
        return;
      }
      if (code === 'CHANNEL_NOT_FOUND' || code === 'MLS_NOT_FOUND') {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Not found', statusCode: 404 });
        return;
      }
      const status = CONFLICT_CODES.has(code) ? 409 : FORBIDDEN_CODES.has(code) ? 403 : 0;
      if (!status) {
        next(error);
        return;
      }
      res.status(status).json({
        error: 'GROUP_STATE_CHANGED',
        code,
        message: 'The conversation could not be prepared. Try again.',
        statusCode: status,
      });
    }
  };

const io = (req: AuthRequest) => req.app.get('io') as SocketServer | undefined;

router.get(
  '/mls/group/pending',
  authMiddleware,
  readLimit,
  handle(async (req, res) => {
    const query = mlsGroupPendingQuery.parse(req.query);
    res.setHeader('Cache-Control', 'no-store');
    res.json(await service.pendingGroupWork(req.userId!, req.deviceId!, query.cursor));
  }),
);

router.get(
  '/channels/:id/mls/group/packages',
  authMiddleware,
  readLimit,
  requireChannelAccess('id'),
  handle(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(await service.listPendingPackages(req.params.id, req.userId!, req.deviceId!));
  }),
);

router.post(
  '/channels/:id/mls/group/packages',
  authMiddleware,
  packageLimit,
  requireChannelAccess('id'),
  handle(async (req, res) => {
    const body = mlsMemberPackageRequest.parse(req.body);
    const result = await service.publishMemberPackage(req.params.id, req.userId!, req.deviceId!, body);
    // Members can now add this device (or re-add it after a rejoin request).
    if (result.created) void emitChannelKeyState(io(req), [req.params.id]);
    res.status(result.created ? 201 : 200).json({ success: true });
  }),
);

router.get(
  '/channels/:id/mls/group/commits',
  authMiddleware,
  readLimit,
  requireChannelAccess('id'),
  handle(async (req, res) => {
    const query = mlsGroupCommitsQuery.parse(req.query);
    res.setHeader('Cache-Control', 'no-store');
    res.json(await service.listGroupCommits(req.params.id, req.userId!, req.deviceId!, query.after, query.limit));
  }),
);

router.get(
  '/channels/:id/mls/group/members',
  authMiddleware,
  readLimit,
  requireChannelAccess('id'),
  handle(async (req, res) => {
    const query = mlsGroupMembersQuery.parse(req.query);
    res.setHeader('Cache-Control', 'no-store');
    res.json(await service.listGroupMembers(req.params.id, req.userId!, req.deviceId!, query.version));
  }),
);

router.post(
  ['/channels/:id/mls/group/commits', '/channels/:id/mls/group/fresh-start'],
  authMiddleware,
  commitLimit,
  requireChannelAccess('id'),
  handle(async (req, res) => {
    const fresh = req.path.endsWith('/fresh-start')
      ? mlsGroupFreshStartRequest.parse(req.body)
      : null;
    const { commit } = fresh ?? mlsGroupCommitRequest.parse(req.body);
    if (commit.channelId !== req.params.id) {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid request', statusCode: 400 });
      return;
    }
    const result = await service.admitGroupCommit(
      req.userId!,
      req.deviceId!,
      commit,
      fresh ? { signature: fresh.freshStartSignature, stepUpProof: req.stepUpProof } : null,
    );
    if (result.replay) {
      res.json({ version: result.version, epoch: result.epoch, replay: true });
      return;
    }
    const server = io(req);
    void emitChannelKeyState(server, [req.params.id]);
    // Earlier messages became unreadable for this conversation's members.
    for (const userId of result.notifyUserIds) {
      server?.to(`user:${userId}`).emit('attention:new', {
        notificationId: randomUUID(),
        workspaceId: result.workspaceId,
        channelId: req.params.id,
        kind: 'channel-restarted',
      } satisfies WsAttentionNotification);
    }
    res.status(201).json({ version: result.version, epoch: result.epoch });
  }),
);

export default router;
