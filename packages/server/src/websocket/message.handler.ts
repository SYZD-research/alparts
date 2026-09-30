import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import {
  MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE,
  MAX_MESSAGE_LENGTH,
  Permissions,
  type ForumTag,
  type WsAttentionNotification,
  type WsForumPostRemoved,
  type WsForumPostUpdated,
  type WsForumTagsUpdated,
} from '@alparts/shared';
import * as messageService from '../services/message.service.js';
import type { ForumPostBroadcastState } from '../services/forum-state.js';
import { logError } from '../security/logger.js';
import { authorizeSocketChannel, consumeSocketRate, type AuthenticatedSocket } from './security.js';

const ciphertextMax = Math.ceil((MAX_MESSAGE_LENGTH * 4 + 16) / 3) * 4;
const uuid = z.string().uuid();
const cryptoFields = {
  deviceId: z.string().uuid(),
  keyVersion: z.number().int().min(1).max(1_000_000),
  idempotencyKey: z.string().uuid(),
  signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
};
const encryptedContent = z.string().min(24).max(ciphertextMax).regex(/^[A-Za-z0-9+/]+={0,2}$/);
const contentNonce = z.string().length(16).regex(/^[A-Za-z0-9+/]+$/);
// Forum replies only; posts are started over HTTP with their tags.
const postId = z.string().uuid().optional();
const sendSchema = z.object({
  channelId: z.string().uuid(),
  encryptedContent,
  contentNonce,
  refMessageId: z.string().uuid().optional(),
  postId,
  broadcastMention: z.boolean(),
  mentionedUserIds: z.array(uuid)
    .max(MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE)
    .refine((ids) => new Set(ids).size === ids.length)
    .optional(),
  ...cryptoFields,
}).strict();
const editSchema = z.object({
  messageId: z.string().uuid(),
  channelId: z.string().uuid(),
  encryptedContent,
  contentNonce,
  broadcastMention: z.boolean(),
  postId,
  ...cryptoFields,
}).strict();
const deleteSchema = z.object({
  messageId: z.string().uuid(),
  channelId: z.string().uuid(),
  postId,
  ...cryptoFields,
}).strict();

type StoredMessageResult = Awaited<ReturnType<typeof messageService.createMessage>>;
type MessageEvent = StoredMessageResult['event'];
type MessageDeletedResult = Awaited<ReturnType<typeof messageService.deleteMessage>>;
export type MessageDeletedPayload = Pick<MessageDeletedResult, 'messageId' | 'channelId' | 'event'>;
export type ReactionUpdatedPayload = Awaited<ReturnType<typeof messageService.toggleReaction>>;
export type PinUpdatedPayload = Awaited<ReturnType<typeof messageService.pinMessage>>;

export function broadcastMessageCreated(
  io: SocketServer,
  message: MessageEvent,
  attentionRecipients: StoredMessageResult['attentionRecipients'] = [],
  forumPost: ForumPostBroadcastState | null = null,
) {
  io.to(`channel:${message.channelId}`).emit('message:new', { message });
  if (forumPost) broadcastForumPostUpdated(io, forumPost);
  for (const recipient of attentionRecipients) {
    io.to(`user:${recipient.userId}`).emit('attention:new', {
      notificationId: message.id,
      workspaceId: recipient.workspaceId,
      channelId: message.channelId,
      ...(forumPost ? { postId: forumPost.postId } : {}),
      kind: recipient.kind,
    } satisfies WsAttentionNotification);
  }
}

export function broadcastForumPostUpdated(io: SocketServer, state: ForumPostBroadcastState) {
  io.to(`channel:${state.channelId}`).emit('forum:post-updated', { channelId: state.channelId, state } satisfies WsForumPostUpdated);
}

export function broadcastForumPostRemoved(io: SocketServer, channelId: string, postId: string) {
  io.to(`channel:${channelId}`).emit('forum:post-removed', { channelId, postId } satisfies WsForumPostRemoved);
}

export function broadcastForumTagsUpdated(io: SocketServer, channelId: string, tags: ForumTag[]) {
  io.to(`channel:${channelId}`).emit('forum:tags-updated', { channelId, tags } satisfies WsForumTagsUpdated);
}

export function broadcastMessageEdited(io: SocketServer, message: MessageEvent) {
  io.to(`channel:${message.channelId}`).emit('message:edited', { message });
}

export function broadcastMessageDeleted(
  io: SocketServer,
  payload: MessageDeletedPayload,
  forum?: Pick<MessageDeletedResult, 'forumPostId' | 'forumPost' | 'forumPostRemoved'>,
) {
  io.to(`channel:${payload.channelId}`).emit('message:deleted', payload);
  if (forum?.forumPostRemoved && forum.forumPostId) broadcastForumPostRemoved(io, payload.channelId, forum.forumPostId);
  if (forum?.forumPost) broadcastForumPostUpdated(io, forum.forumPost);
}

export function broadcastReactionUpdated(io: SocketServer, payload: ReactionUpdatedPayload) {
  io.to(`channel:${payload.channelId}`).emit('message:reaction', payload);
}

export function broadcastPinUpdated(io: SocketServer, payload: PinUpdatedPayload) {
  io.to(`channel:${payload.channelId}`).emit('message:pinned', payload);
}

export function handleMessageEvents(io: SocketServer, socket: AuthenticatedSocket) {
  socket.on('message:send', async (data: unknown) => {
    try {
      if (!consumeSocketRate(socket, 'message-write', 60, 60_000)) throw new Error('RATE_LIMITED');
      const value = sendSchema.parse(data);
      if (value.deviceId !== socket.deviceId) throw new Error('DEVICE_MISMATCH');
      if (!await authorizeSocketChannel(socket, value.channelId, Permissions.SEND_MESSAGES)) throw new Error('FORBIDDEN');
      const result = await messageService.createMessage(
        value.channelId,
        socket.userId!,
        value,
        value.refMessageId,
        value.mentionedUserIds,
      );
      if (result.isNewEvent) broadcastMessageCreated(io, result.event, result.attentionRecipients, result.forumPost);
    } catch (error) {
      logError('websocket.message_send', error);
      socket.emit('operation:error', { code: 'MESSAGE_REJECTED' });
    }
  });

  socket.on('message:edit', async (data: unknown) => {
    try {
      if (!consumeSocketRate(socket, 'message-write', 60, 60_000)) throw new Error('RATE_LIMITED');
      const value = editSchema.parse(data);
      if (value.deviceId !== socket.deviceId) throw new Error('DEVICE_MISMATCH');
      if (!await authorizeSocketChannel(socket, value.channelId, Permissions.EDIT_MESSAGES)) throw new Error('FORBIDDEN');
      const result = await messageService.editMessage(value.messageId, socket.userId!, value);
      if (result.isNewEvent) broadcastMessageEdited(io, result.event);
    } catch (error) {
      logError('websocket.message_edit', error);
      socket.emit('operation:error', { code: 'MESSAGE_REJECTED' });
    }
  });

  socket.on('message:delete', async (data: unknown) => {
    try {
      if (!consumeSocketRate(socket, 'message-write', 60, 60_000)) throw new Error('RATE_LIMITED');
      const value = deleteSchema.parse(data);
      if (value.deviceId !== socket.deviceId) throw new Error('DEVICE_MISMATCH');
      if (!await authorizeSocketChannel(socket, value.channelId, Permissions.DELETE_MESSAGES)) throw new Error('FORBIDDEN');
      const result = await messageService.deleteMessage(value.messageId, socket.userId!, {
        ...value,
        encryptedContent: '',
        contentNonce: '',
        broadcastMention: false,
      });
      if (result.isNewEvent) {
        broadcastMessageDeleted(io, {
          messageId: result.messageId,
          channelId: result.channelId,
          event: result.event,
        }, result);
      }
    } catch (error) {
      logError('websocket.message_delete', error);
      socket.emit('operation:error', { code: 'MESSAGE_REJECTED' });
    }
  });
}
