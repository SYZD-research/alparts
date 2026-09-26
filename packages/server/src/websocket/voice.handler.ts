import type { Server as SocketServer } from 'socket.io';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import {
  MAX_VOICE_PARTICIPANTS,
  Permissions,
  type SignedVoiceSignalEnvelope,
  type VoiceChannelPresence,
  type VoiceIceServer,
  type VoiceParticipant,
} from '@alparts/shared';
import { eq } from 'drizzle-orm';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { channels } from '../db/schema.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
} from '../services/authorization.service.js';
import { logError } from '../security/logger.js';
import { MAX_CHANNELS_PER_WORKSPACE } from '../security/limits.js';
import { authorizeSocketChannel, consumeSocketRate, type AuthenticatedSocket } from './security.js';
import { VOICE_PRESENCE_ROOM_PREFIX, voicePresenceRoom } from './voice-rooms.js';

const uuid = z.string().uuid();
const participantId = z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/);
const signature = z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/);
const nullableText = z.string().max(256).nullable();
const signalBase = {
  type: z.literal('voice-signal'),
  signalId: uuid,
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  channelId: uuid,
  senderParticipantId: participantId,
  senderDeviceId: uuid,
  targetParticipantId: participantId,
  signature,
};
const voiceSignalSchema = z.discriminatedUnion('kind', [
  z.object({
    ...signalBase,
    kind: z.literal('offer'),
    descriptionType: z.literal('offer'),
    sdp: z.string().min(1).max(32 * 1024),
    candidate: z.null(),
    sdpMid: z.null(),
    sdpMLineIndex: z.null(),
    usernameFragment: z.null(),
  }).strict(),
  z.object({
    ...signalBase,
    kind: z.literal('answer'),
    descriptionType: z.literal('answer'),
    sdp: z.string().min(1).max(32 * 1024),
    candidate: z.null(),
    sdpMid: z.null(),
    sdpMLineIndex: z.null(),
    usernameFragment: z.null(),
  }).strict(),
  z.object({
    ...signalBase,
    kind: z.literal('ice'),
    descriptionType: z.null(),
    sdp: z.null(),
    candidate: z.string().min(1).max(2_048),
    sdpMid: nullableText,
    sdpMLineIndex: z.number().int().min(0).max(65_535).nullable(),
    usernameFragment: nullableText,
  }).strict(),
]);
const joinSchema = z.object({ channelId: uuid }).strict();
const leaveSchema = z.object({ channelId: uuid }).strict();
const watchSchema = z.object({
  channelIds: z.array(uuid).max(MAX_CHANNELS_PER_WORKSPACE).refine((ids) => new Set(ids).size === ids.length),
}).strict();
const stateSchema = z.object({
  channelId: uuid,
  muted: z.boolean(),
  speaking: z.boolean(),
}).strict();

interface StoredVoiceParticipant extends VoiceParticipant {
  socketId: string;
  channelId: string;
}

export class VoiceParticipantRegistry {
  private readonly bySocket = new Map<string, StoredVoiceParticipant>();
  private readonly byParticipant = new Map<string, StoredVoiceParticipant>();
  private readonly byChannel = new Map<string, Map<string, StoredVoiceParticipant>>();

  constructor(private readonly maxParticipantsPerChannel = MAX_VOICE_PARTICIPANTS) {
    if (!Number.isSafeInteger(maxParticipantsPerChannel) || maxParticipantsPerChannel < 1) {
      throw new Error('Invalid voice participant limit');
    }
  }

  join(
    socketId: string,
    userId: string,
    deviceId: string,
    channelId: string,
    now = new Date(),
    publicParticipantId: string = randomUUID(),
  ): { participant: VoiceParticipant; existing: VoiceParticipant[]; previous: StoredVoiceParticipant | null; joined: boolean } {
    const current = this.bySocket.get(socketId);
    if (current?.channelId === channelId) {
      return {
        participant: publicParticipant(current),
        existing: this.list(channelId).filter((entry) => entry.participantId !== current.participantId),
        previous: null,
        joined: false,
      };
    }
    if (this.byParticipant.has(publicParticipantId)) throw new Error('VOICE_PARTICIPANT_ID_CONFLICT');
    const previous = current ? this.leave(socketId) : null;
    const channel = this.byChannel.get(channelId) ?? new Map<string, StoredVoiceParticipant>();
    if (channel.size >= this.maxParticipantsPerChannel) {
      if (previous) this.restore(previous);
      throw new Error('VOICE_CHANNEL_FULL');
    }
    const existing = [...channel.values()].map(publicParticipant);
    const participant: StoredVoiceParticipant = {
      participantId: publicParticipantId,
      socketId,
      userId,
      deviceId,
      channelId,
      muted: false,
      speaking: false,
      joinedAt: now.toISOString(),
    };
    channel.set(publicParticipantId, participant);
    this.byChannel.set(channelId, channel);
    this.bySocket.set(socketId, participant);
    this.byParticipant.set(publicParticipantId, participant);
    return { participant: publicParticipant(participant), existing, previous, joined: true };
  }

  leave(socketId: string): StoredVoiceParticipant | null {
    const participant = this.bySocket.get(socketId);
    if (!participant) return null;
    this.bySocket.delete(socketId);
    this.byParticipant.delete(participant.participantId);
    const channel = this.byChannel.get(participant.channelId);
    channel?.delete(participant.participantId);
    if (channel?.size === 0) this.byChannel.delete(participant.channelId);
    return participant;
  }

  update(
    socketId: string,
    channelId: string,
    state: { muted: boolean; speaking: boolean },
  ): VoiceParticipant | null {
    const participant = this.bySocket.get(socketId);
    if (!participant || participant.channelId !== channelId) return null;
    participant.muted = state.muted;
    participant.speaking = state.muted ? false : state.speaking;
    return publicParticipant(participant);
  }

  get(socketId: string): StoredVoiceParticipant | null {
    return this.bySocket.get(socketId) ?? null;
  }

  getByParticipantId(participantIdValue: string): StoredVoiceParticipant | null {
    return this.byParticipant.get(participantIdValue) ?? null;
  }

  list(channelId: string): VoiceParticipant[] {
    return [...(this.byChannel.get(channelId)?.values() ?? [])]
      .sort((left, right) => left.joinedAt.localeCompare(right.joinedAt)
        || left.participantId.localeCompare(right.participantId))
      .map(publicParticipant);
  }

  canRoute(senderId: string, targetId: string, channelId: string): boolean {
    const sender = this.bySocket.get(senderId);
    const target = this.byParticipant.get(targetId);
    return Boolean(
      sender
      && target
      && sender.participantId !== target.participantId
      && sender.channelId === channelId
      && target.channelId === channelId,
    );
  }

  rollbackJoin(socketId: string, previous: StoredVoiceParticipant | null): void {
    this.leave(socketId);
    if (previous) this.restore(previous);
  }

  private restore(participant: StoredVoiceParticipant): void {
    const channel = this.byChannel.get(participant.channelId) ?? new Map<string, StoredVoiceParticipant>();
    channel.set(participant.participantId, participant);
    this.byChannel.set(participant.channelId, channel);
    this.bySocket.set(participant.socketId, participant);
    this.byParticipant.set(participant.participantId, participant);
  }
}

type JoinAcknowledgement = (result: {
  ok: boolean;
  error?: 'DEVICE_REQUIRED' | 'FORBIDDEN' | 'VOICE_CHANNEL_FULL' | 'INVALID_REQUEST';
  self?: VoiceParticipant;
  participants?: VoiceParticipant[];
  iceServers?: VoiceIceServer[];
}) => void;

type BasicAcknowledgement = (result: { ok: boolean }) => void;
type WatchAcknowledgement = (result: { ok: boolean; channels: VoiceChannelPresence[] }) => void;

export class VoiceSignalingHub {
  readonly registry: VoiceParticipantRegistry;
  private readonly watchVersions = new Map<string, number>();
  private readonly watchQueues = new Map<string, Promise<void>>();

  constructor(
    private readonly io: SocketServer,
    registry = new VoiceParticipantRegistry(),
    private readonly iceServers: VoiceIceServer[] = [...config.voice.iceServers],
  ) {
    this.registry = registry;
    this.io.of('/').adapter.on('leave-room', (room, socketId) => {
      if (room.startsWith('channel:')) this.removeIfChannelRoomLeft(socketId, room.slice('channel:'.length));
    });
  }

  attach(socket: AuthenticatedSocket): void {
    socket.on('voice:watch', async (value: unknown, acknowledge?: WatchAcknowledgement) => {
      if (!consumeSocketRate(socket, 'voice-watch', 30, 60_000)) {
        acknowledge?.({ ok: false, channels: [] });
        return;
      }
      const parsed = watchSchema.safeParse(value);
      if (!parsed.success) {
        acknowledge?.({ ok: false, channels: [] });
        return;
      }
      const version = (this.watchVersions.get(socket.id) ?? 0) + 1;
      this.watchVersions.set(socket.id, version);
      const previous = this.watchQueues.get(socket.id) ?? Promise.resolve();
      const operation = previous.catch(() => undefined).then(async () => {
        if (this.watchVersions.get(socket.id) !== version || !socket.connected) return;
        try {
          const requestedRooms = new Set(parsed.data.channelIds.map(voicePresenceRoom));
          for (const room of socket.rooms) {
            if (this.watchVersions.get(socket.id) !== version || !socket.connected) return;
            if (room.startsWith(VOICE_PRESENCE_ROOM_PREFIX) && !requestedRooms.has(room)) {
              await socket.leave(room);
            }
          }

          const visibleChannelIds: string[] = [];
          for (const channelId of parsed.data.channelIds) {
            if (this.watchVersions.get(socket.id) !== version || !socket.connected) return;
            if (await this.joinPresenceUnderAuthorizationLock(socket, channelId)) {
              visibleChannelIds.push(channelId);
            }
          }
          if (this.watchVersions.get(socket.id) === version && socket.connected) {
            // Snapshot all authorized rooms in one JS turn so an older per-room
            // snapshot cannot overwrite a newer presence event at the client.
            const visible = visibleChannelIds.map((channelId) => ({
              channelId,
              participants: this.registry.list(channelId),
            }));
            acknowledge?.({ ok: true, channels: visible });
          }
        } catch (error) {
          logError('websocket.voice_watch', error);
          if (this.watchVersions.get(socket.id) === version) acknowledge?.({ ok: false, channels: [] });
        }
      });
      this.watchQueues.set(socket.id, operation);
      await operation;
      if (this.watchQueues.get(socket.id) === operation) this.watchQueues.delete(socket.id);
    });

    socket.on('voice:join', async (value: unknown, acknowledge?: JoinAcknowledgement) => {
      if (!consumeSocketRate(socket, 'voice-join', 20, 60_000)) {
        acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
        return;
      }
      const parsed = joinSchema.safeParse(value);
      if (!parsed.success) {
        acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
        return;
      }
      if (!socket.deviceId) {
        acknowledge?.({ ok: false, error: 'DEVICE_REQUIRED' });
        return;
      }
      try {
        const authorized = await this.joinUnderAuthorizationLock(socket, parsed.data.channelId);
        if (!authorized) {
          acknowledge?.({ ok: false, error: 'FORBIDDEN' });
          return;
        }
        const joined = this.registry.join(
          socket.id,
          socket.userId!,
          socket.deviceId,
          parsed.data.channelId,
        );
        // Authorization revocation can finish between the database lock being
        // released and this continuation resuming. Registry mutation and this
        // postcondition run in one JS turn: either the room was already
        // removed and we roll back, or a later adapter leave event removes the
        // newly registered participant.
        if (!socket.connected || !socket.rooms.has(`channel:${parsed.data.channelId}`)) {
          this.registry.rollbackJoin(socket.id, joined.previous);
          acknowledge?.({ ok: false, error: 'FORBIDDEN' });
          return;
        }
        if (joined.previous) {
          try {
            await socket.leave(`channel:${joined.previous.channelId}`);
          } catch (error) {
            logError('websocket.voice_switch_room', error);
          }
          this.notifyParticipantLeft(joined.previous);
        }
        if (joined.joined) this.notifyParticipants(
          parsed.data.channelId,
          'voice:participant-joined',
          joined.participant,
          joined.participant.participantId,
        );
        this.broadcastPresence(parsed.data.channelId);
        acknowledge?.({
          ok: true,
          self: joined.participant,
          participants: joined.existing,
          iceServers: this.iceServers,
        });
      } catch (error) {
        if (this.registry.get(socket.id)?.channelId !== parsed.data.channelId) {
          void Promise.resolve(socket.leave(`channel:${parsed.data.channelId}`))
            .catch((leaveError) => logError('websocket.voice_join_cleanup', leaveError));
        }
        if (error instanceof Error && error.message === 'VOICE_CHANNEL_FULL') {
          acknowledge?.({ ok: false, error: 'VOICE_CHANNEL_FULL' });
          return;
        }
        logError('websocket.voice_join', error);
        acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
      }
    });

    socket.on('voice:leave', async (value: unknown, acknowledge?: BasicAcknowledgement) => {
      const parsed = leaveSchema.safeParse(value);
      const current = this.registry.get(socket.id);
      if (!parsed.success || !current || current.channelId !== parsed.data.channelId) {
        acknowledge?.({ ok: false });
        return;
      }
      const departed = this.registry.leave(socket.id);
      if (departed) {
        try {
          await socket.leave(`channel:${departed.channelId}`);
        } catch (error) {
          logError('websocket.voice_leave_room', error);
        }
        this.notifyParticipantLeft(departed);
      }
      acknowledge?.({ ok: true });
    });

    socket.on('voice:state', (value: unknown) => {
      if (!consumeSocketRate(socket, 'voice-state', 120, 60_000)) return;
      const parsed = stateSchema.safeParse(value);
      if (!parsed.success || !socket.rooms.has(`channel:${parsed.data.channelId}`)) return;
      const participant = this.registry.update(socket.id, parsed.data.channelId, parsed.data);
      if (participant) this.notifyParticipants(
        parsed.data.channelId,
        'voice:participant-updated',
        participant,
        participant.participantId,
      );
      if (participant) this.broadcastPresence(parsed.data.channelId);
    });

    socket.on('voice:signal', (value: unknown, acknowledge?: BasicAcknowledgement) => {
      if (!consumeSocketRate(socket, 'voice-signal', 600, 60_000)) {
        acknowledge?.({ ok: false });
        return;
      }
      const parsed = voiceSignalSchema.safeParse(value);
      if (!parsed.success) {
        acknowledge?.({ ok: false });
        return;
      }
      const { signature: signalSignature, ...envelope } = parsed.data;
      const senderParticipant = this.registry.get(socket.id);
      const targetParticipant = this.registry.getByParticipantId(envelope.targetParticipantId);
      const targetSocket = targetParticipant
        ? this.io.sockets.sockets.get(targetParticipant.socketId)
        : undefined;
      if (
        envelope.senderParticipantId !== senderParticipant?.participantId
        || envelope.senderDeviceId !== socket.deviceId
        || !this.registry.canRoute(socket.id, envelope.targetParticipantId, envelope.channelId)
        || !socket.rooms.has(`channel:${envelope.channelId}`)
        || !targetSocket?.rooms.has(`channel:${envelope.channelId}`)
      ) {
        acknowledge?.({ ok: false });
        return;
      }
      targetSocket.emit('voice:signal', {
        envelope: envelope as SignedVoiceSignalEnvelope,
        signature: signalSignature,
      });
      acknowledge?.({ ok: true });
    });

    socket.once('disconnect', () => {
      this.watchVersions.delete(socket.id);
      this.watchQueues.delete(socket.id);
    });
  }

  private async joinUnderAuthorizationLock(socket: AuthenticatedSocket, channelId: string): Promise<boolean> {
    if (!await authorizeSocketChannel(socket, channelId, (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE))) return false;
    const location = await db.query.channels.findFirst({
      columns: { workspaceId: true, type: true },
      where: eq(channels.id, channelId),
    });
    if (!location || location.type !== 'voice') return false;
    return db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
      const authorization = await getChannelAuthorizationFromStore(transaction, socket.userId!, channelId);
      if (
        !socket.connected
        || authorization?.workspaceId !== location.workspaceId
        || !isVisibleChannelAuthorization(authorization)
        || (authorization.permissions & (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE)) !== (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE)
      ) return false;
      const channelRoom = `channel:${channelId}`;
      const presenceRoom = voicePresenceRoom(channelId);
      if (!socket.rooms.has(channelRoom) || !socket.rooms.has(presenceRoom)) {
        await socket.join([channelRoom, presenceRoom]);
      }
      return socket.connected && socket.rooms.has(channelRoom) && socket.rooms.has(presenceRoom);
    });
  }

  private async joinPresenceUnderAuthorizationLock(socket: AuthenticatedSocket, channelId: string): Promise<boolean> {
    if (!await authorizeSocketChannel(socket, channelId, (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE))) return false;
    const location = await db.query.channels.findFirst({
      columns: { workspaceId: true, type: true },
      where: eq(channels.id, channelId),
    });
    if (!location || location.type !== 'voice') return false;
    return db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
      const authorization = await getChannelAuthorizationFromStore(transaction, socket.userId!, channelId);
      if (
        !socket.connected
        || authorization?.workspaceId !== location.workspaceId
        || !isVisibleChannelAuthorization(authorization)
        || (authorization.permissions & (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE)) !== (Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE)
      ) return false;
      const room = voicePresenceRoom(channelId);
      if (!socket.rooms.has(room)) await socket.join(room);
      return socket.connected && socket.rooms.has(room);
    });
  }

  private removeIfChannelRoomLeft(socketId: string, channelId: string): void {
    const participant = this.registry.get(socketId);
    if (!participant || participant.channelId !== channelId) return;
    const departed = this.registry.leave(socketId);
    if (departed) this.notifyParticipantLeft(departed);
  }

  private notifyParticipantLeft(participant: StoredVoiceParticipant): void {
    this.notifyParticipants(
      participant.channelId,
      'voice:participant-left',
      { channelId: participant.channelId, participantId: participant.participantId },
      participant.participantId,
    );
    this.broadcastPresence(participant.channelId);
  }

  private broadcastPresence(channelId: string): void {
    this.io.to(voicePresenceRoom(channelId)).emit('voice:participants-changed', {
      channelId,
      participants: this.registry.list(channelId),
    } satisfies VoiceChannelPresence);
  }

  private notifyParticipants(channelId: string, event: string, payload: unknown, excludedId?: string): void {
    for (const participant of this.registry.list(channelId)) {
      const stored = this.registry.getByParticipantId(participant.participantId);
      if (stored && participant.participantId !== excludedId) this.io.to(stored.socketId).emit(event, payload);
    }
  }
}

function publicParticipant(participant: StoredVoiceParticipant): VoiceParticipant {
  return {
    participantId: participant.participantId,
    userId: participant.userId,
    deviceId: participant.deviceId,
    muted: participant.muted,
    speaking: participant.speaking,
    joinedAt: participant.joinedAt,
  };
}

export function parseVoiceSignal(value: unknown): { envelope: SignedVoiceSignalEnvelope; signature: string } | null {
  const parsed = voiceSignalSchema.safeParse(value);
  if (!parsed.success) return null;
  const { signature: signalSignature, ...envelope } = parsed.data;
  return { envelope: envelope as SignedVoiceSignalEnvelope, signature: signalSignature };
}
