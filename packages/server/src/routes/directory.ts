import { requireApprovedDevice } from '../services/passkey.service.js';
import { isAccountSecurityError } from '../security/account-errors.js';
import { Router } from 'express';
import { z } from 'zod';
import { and, eq, sql } from 'drizzle-orm';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { readDirectory } from '../services/directory.service.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
  getChannelViewerIdsFromStore,
} from '../services/authorization.service.js';
import { db } from '../db/index.js';
import { messages, channels, channelKeyEpochRecipients } from '../db/schema.js';
const router = Router();
router.get('/directory/:userId', authMiddleware, async (req: AuthRequest, res) => {
  const query = z
    .object({
      after: z.coerce.number().int().min(0).max(8192).default(0),
      channelId: z.string().uuid().optional(),
    })
    .strict()
    .safeParse(req.query);
  if (!query.success || !z.string().uuid().safeParse(req.params.userId).success) {
    res.sendStatus(400);
    return;
  }
  try {
    const result = await db.transaction(async (tx) => {
      let ceiling = 8192;
      if (req.params.userId !== req.userId) {
        await requireApprovedDevice(tx, req.userId!, req.sessionId!);
        const channelId = query.data.channelId;
        if (!channelId) throw new Error('NOT_AUTHORIZED');
        const channel = await tx.query.channels.findFirst({
          where: eq(channels.id, channelId),
        });
        if (!channel) throw new Error('NOT_AUTHORIZED');
        await lockWorkspaceForAuthorization(tx, channel.workspaceId, 'share');
        if (
          !isVisibleChannelAuthorization(
            await getChannelAuthorizationFromStore(tx, req.userId!, channelId),
          )
        )
          throw new Error('NOT_AUTHORIZED');
        const viewers = await getChannelViewerIdsFromStore(tx, channel);
        const historical = await tx.query.messages.findFirst({
          columns: { id: true },
          where: and(eq(messages.channelId, channelId), eq(messages.authorId, req.params.userId)),
        });
        const recipient = await tx.query.channelKeyEpochRecipients.findFirst({
          columns: { deviceId: true },
          where: and(
            eq(channelKeyEpochRecipients.channelId, channelId),
            eq(channelKeyEpochRecipients.userId, req.params.userId),
          ),
        });
        if (!viewers.includes(req.params.userId) && !historical && !recipient) {
          throw new Error('NOT_AUTHORIZED');
        }
        if (!viewers.includes(req.params.userId)) {
          // Former members expose only the prefix used by this channel's signed
          // epochs (or the pinned legacy migration prefix), never future events.
          const cap = await tx.execute(sql`select greatest(
        coalesce((select sequence from channel_directory_heads
          where channel_id = ${channelId} and user_id = ${req.params.userId}), 0),
        coalesce((select max(sequence) from device_directory_events
          where user_id = ${req.params.userId} and event->>'kind' = 'legacy'), 0)
      ) as ceiling`);
          ceiling = Number(cap.rows[0]?.ceiling ?? 0);
        }
      }
      return readDirectory(
        req.params.userId,
        query.data.after,
        ceiling,
        tx as unknown as typeof db,
      );
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json(result);
  } catch (error) {
    if (!isAccountSecurityError(error)) throw error;
    res.sendStatus(403);
  }
});
export default router;
