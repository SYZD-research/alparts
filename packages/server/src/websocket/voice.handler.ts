import type { VoiceCoordinator } from '../voice/voice-coordinator.js';
import type { Server as SocketServer } from 'socket.io';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { canonicalUuid } from '../security/canonical-id.js';
import {
  MAX_VOICE_PARTICIPANTS,
  Permissions,
  type SignedVoiceKeyEnvelope,
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

// Channel ids name rooms; only the stored (lowercase) form is accepted.
const uuid = canonicalUuid;
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
// A client may pick its own participant id (a fresh random UUID per call), so
// that key messages sent to it in an earlier call cannot be presented again.
const joinSchema = z.object({ channelId: uuid, participantId: uuid.optional() }).strict();
const sfuJoinSchema = z.object({ channelId: uuid }).strict();
const leaveSchema = z.object({ channelId: uuid }).strict();
const voiceKeySchema = z.object({
  type: z.literal('voice-key'),
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  channelId: uuid,
  senderParticipantId: participantId,
  senderDeviceId: uuid,
  targetParticipantId: participantId,
  targetDeviceId: uuid,
  keyId: z.number().int().min(0).max(0xffff_ffff),
  // RSA-OAEP of 32 bytes under a 2048- to 8192-bit key, base64.
  wrappedKey: z.string().min(344).max(1368).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  signature,
}).strict();
/** Media parameters are checked by mediasoup itself; here only their size is bounded. */
const MAX_MEDIA_PARAMETERS_BYTES = 16 * 1024;
const mediaParameters = z.record(z.string(), z.unknown()).refine((value) => {
  try {
    return JSON.stringify(value).length <= MAX_MEDIA_PARAMETERS_BYTES;
  } catch {
    return false;
  }
});
const mediaId = z.string().min(1).max(64).regex(/^[0-9a-f-]+$/);
const direction = z.enum(['send', 'recv']);
const sfuTransportSchema = z.object({ channelId: uuid, direction }).strict();
const sfuConnectSchema = z.object({ channelId: uuid, direction, transportId: mediaId, dtlsParameters: mediaParameters }).strict();
const sfuProduceSchema = z.object({ channelId: uuid, rtpParameters: mediaParameters }).strict();
const sfuConsumeSchema = z.object({ channelId: uuid, sourceParticipantId: participantId, rtpCapabilities: mediaParameters }).strict();
const sfuResumeSchema = z.object({ channelId: uuid, consumerId: mediaId }).strict();
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
  /** Present when calls go through the media server; absent for direct (P2P) calls. */
  media?: 'sfu';
}) => void;

type BasicAcknowledgement = (result: { ok: boolean }) => void;
type WatchAcknowledgement = (result: { ok: boolean; channels: VoiceChannelPresence[] }) => void;

export class VoiceSignalingHub {
  readonly registry: VoiceParticipantRegistry;
  /** 'sfu' once the media server has started: calls then go through it, with frame encryption. */
  private media: 'p2p' | 'sfu' = 'p2p';
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

  /** Route calls through the media server (startVoiceSfu calls this once it has started). */
  enableSfu(): void {
    this.media = 'sfu';
  }

  get sfuEnabled(): boolean {
    return this.media === 'sfu';
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
            // A channel whose access was revoked while later channels were
            // checked has already left its room; it is not listed.
            const visible = visibleChannelIds
              .filter((channelId) => socket.rooms.has(voicePresenceRoom(channelId)))
              .map((channelId) => ({
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
      // Calls through the media server need clients that encrypt frames, and
      // those pick their own participant id.
      if (this.sfuEnabled && !parsed.data.participantId) {
        acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
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
          new Date(),
          parsed.data.participantId,
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
          ...(this.sfuEnabled ? { media: 'sfu' as const } : {}),
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
      // Calls through the media server have no direct connections to set up.
      if (this.sfuEnabled || !consumeSocketRate(socket, 'voice-signal', 600, 60_000)) {
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

    // Frame keys of calls through the media server: relayed, like signals,
    // only between two current participants of the same call. The server
    // cannot read them (they are encrypted to the target device) or change
    // them (they are signed by the sender device).
    socket.on('voice:key', (value: unknown, acknowledge?: BasicAcknowledgement) => {
      if (!this.sfuEnabled || !consumeSocketRate(socket, 'voice-key', 600, 60_000)) {
        acknowledge?.({ ok: false });
        return;
      }
      const parsed = voiceKeySchema.safeParse(value);
      if (!parsed.success) {
        acknowledge?.({ ok: false });
        return;
      }
      const { signature: keySignature, ...envelope } = parsed.data;
      const senderParticipant = this.registry.get(socket.id);
      const targetParticipant = this.registry.getByParticipantId(envelope.targetParticipantId);
      const targetSocket = targetParticipant
        ? this.io.sockets.sockets.get(targetParticipant.socketId)
        : undefined;
      if (
        envelope.senderParticipantId !== senderParticipant?.participantId
        || envelope.senderDeviceId !== socket.deviceId
        || envelope.targetDeviceId !== targetParticipant?.deviceId
        || !this.registry.canRoute(socket.id, envelope.targetParticipantId, envelope.channelId)
        || !socket.rooms.has(`channel:${envelope.channelId}`)
        || !targetSocket?.rooms.has(`channel:${envelope.channelId}`)
      ) {
        acknowledge?.({ ok: false });
        return;
      }
      targetSocket.emit('voice:key', {
        envelope: envelope as SignedVoiceKeyEnvelope,
        signature: keySignature,
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

type VoiceSfuJoinAcknowledgement = (result:
	| {
		ok: true;
		participantId: string;
		rtpCapabilities: Awaited<ReturnType<VoiceCoordinator['joinParticipant']>>;
		/** Streams already being sent in the call, by participant. */
		producers: Array<{ participantId: string; producerId: string }>;
	}
	| {
		ok: false;
		error: 'INVALID_REQUEST' | 'ALREADY_JOINED' | 'FORBIDDEN' | 'VOICE_CHANNEL_FULL' | 'SFU_UNAVAILABLE';
	}
) => void;

type ResultAcknowledgement<T> = (result: ({ ok: true } & T) | { ok: false }) => void;

/**
 * Media through the SFU for the participants of the call registry: the SFU
 * session of a socket is that of its registry participant (same id, same
 * channel), and ends with it, since leaving the call or losing access leaves
 * the channel room. Frames are encrypted end to end by the clients (SFrame);
 * the SFU forwards them.
 */
export function attachVoiceSfuEvents(
	io: SocketServer,
	coordinator: VoiceCoordinator,
	hub: VoiceSignalingHub,
	authorize: (socket: AuthenticatedSocket, channelId: string) => Promise<boolean> = authorizeSfuVoiceChannel,
): void {
	const sessions = new Map<string, {
		channelId: string;
		participantId: string;
	}>();

	const release = (socketId: string): void => {
		const session = sessions.get(socketId);

		if (!session) {
			return;
		}

		sessions.delete(socketId);
		coordinator.leaveParticipant(session.participantId);
	};

	io.of('/').adapter.on('leave-room', (room, socketId) => {
		const session = sessions.get(socketId);

		if (session && room === `channel:${session.channelId}`) {
			release(socketId);
		}
	});

	/** The socket's current SFU session in this channel, still in the call registry and the room. */
	const current = (socket: AuthenticatedSocket, channelId: string) => {
		const session = sessions.get(socket.id);
		const registered = hub.registry.get(socket.id);
		if (
			!session
			|| session.channelId !== channelId
			|| registered?.channelId !== channelId
			|| registered.participantId !== session.participantId
			|| !socket.connected
			|| !socket.rooms.has(`channel:${channelId}`)
		) {
			return null;
		}
		return session;
	};

	/** One media request: rate limited, validated, on the current session, answered once. */
	const handle = <S extends z.ZodTypeAny, T extends object>(
		socket: AuthenticatedSocket,
		event: string,
		limit: number,
		schema: S,
		run: (session: { channelId: string; participantId: string }, input: z.infer<S>) => Promise<T>,
	) => {
		socket.on(event, async (value: unknown, acknowledge?: ResultAcknowledgement<T>) => {
			if (!consumeSocketRate(socket, event.replaceAll(':', '-'), limit, 60_000)) {
				acknowledge?.({ ok: false });
				return;
			}
			const parsed = schema.safeParse(value);
			const session = parsed.success ? current(socket, (parsed.data as { channelId: string }).channelId) : null;
			if (!parsed.success || !session) {
				acknowledge?.({ ok: false });
				return;
			}
			try {
				const result = await run(session, parsed.data);
				if (current(socket, session.channelId) !== session) {
					acknowledge?.({ ok: false });
					return;
				}
				acknowledge?.({ ok: true, ...result });
			} catch (error) {
				if (!(error instanceof Error) || !/^VOICE_|^INVALID_/.test(error.message)) {
					logError(`websocket.${event.replaceAll(':', '_')}`, error);
				}
				acknowledge?.({ ok: false });
			}
		});
	};

	io.on('connection', (socket: AuthenticatedSocket) => {
		socket.on('voice:sfu:join', async (
			value: unknown,
			acknowledge?: VoiceSfuJoinAcknowledgement,
		) => {
			if (!consumeSocketRate(socket, 'voice-sfu-join', 20, 60_000)) {
				acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
				return;
			}

			const parsed = sfuJoinSchema.safeParse(value);

			if (!parsed.success) {
				acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
				return;
			}

			if (sessions.has(socket.id)) {
				acknowledge?.({ ok: false, error: 'ALREADY_JOINED' });
				return;
			}

			// Only a participant of the call registry gets media, under its own id.
			const registered = hub.registry.get(socket.id);

			if (registered?.channelId !== parsed.data.channelId) {
				acknowledge?.({ ok: false, error: 'FORBIDDEN' });
				return;
			}

			const session = {
				channelId: parsed.data.channelId,
				participantId: registered.participantId,
			};

			sessions.set(socket.id, session);

			try {
				const authorized = await authorize(
					socket,
					session.channelId,
				);

				if (!authorized || sessions.get(socket.id) !== session) {
					throw new Error('VOICE_SFU_FORBIDDEN');
				}

				const rtpCapabilities = await coordinator.joinParticipant(
					session.channelId,
					session.participantId,
				);

				if (current(socket, session.channelId) !== session) {
					throw new Error('VOICE_SFU_FORBIDDEN');
				}

				acknowledge?.({
					ok: true,
					participantId: session.participantId,
					rtpCapabilities,
					producers: coordinator.getProducers(session.channelId)
						.filter((producer) => producer.participantId !== session.participantId),
				});
			} catch (error) {
				if (sessions.get(socket.id) === session) {
					release(socket.id);
				} else {
					coordinator.leaveParticipant(session.participantId);
				}

				if (error instanceof Error && error.message === 'VOICE_CHANNEL_FULL') {
					acknowledge?.({ ok: false, error: 'VOICE_CHANNEL_FULL' });
				} else if (error instanceof Error && error.message === 'VOICE_SFU_FORBIDDEN') {
					acknowledge?.({ ok: false, error: 'FORBIDDEN' });
				} else {
					logError('websocket.voice_sfu_join', error);
					acknowledge?.({ ok: false, error: 'SFU_UNAVAILABLE' });
				}
			}
		});

		socket.on('voice:sfu:leave', (
			value: unknown,
			acknowledge?: BasicAcknowledgement,
		) => {
			const parsed = leaveSchema.safeParse(value);
			const session = sessions.get(socket.id);

			if (!parsed.success || session?.channelId !== parsed.data.channelId) {
				acknowledge?.({ ok: false });
				return;
			}

			release(socket.id);
			acknowledge?.({ ok: true });
		});

		handle(socket, 'voice:sfu:transport', 20, sfuTransportSchema, async (session, input) => ({
			transport: await coordinator.createTransport(session.channelId, session.participantId, input.direction),
		}));

		handle(socket, 'voice:sfu:connect', 20, sfuConnectSchema, async (session, input) => {
			await coordinator.connectTransport(
				session.channelId,
				session.participantId,
				input.direction,
				input.transportId,
				input.dtlsParameters as never,
			);
			return {};
		});

		handle(socket, 'voice:sfu:produce', 20, sfuProduceSchema, async (session, input) => {
			const producerId = await coordinator.createProducer(
				session.channelId,
				session.participantId,
				input.rtpParameters as never,
			);
			// Everyone else in the call starts receiving the new stream.
			for (const [socketId, other] of sessions) {
				if (socketId !== socket.id && other.channelId === session.channelId) {
					io.to(socketId).emit('voice:sfu:producer', {
						channelId: session.channelId,
						participantId: session.participantId,
						producerId,
					});
				}
			}
			return { producerId };
		});

		handle(socket, 'voice:sfu:consume', 120, sfuConsumeSchema, async (session, input) => ({
			consumer: await coordinator.createConsumer(
				session.channelId,
				session.participantId,
				input.sourceParticipantId,
				input.rtpCapabilities as never,
			),
		}));

		handle(socket, 'voice:sfu:resume', 120, sfuResumeSchema, async (session, input) => {
			await coordinator.resumeConsumer(session.channelId, session.participantId, input.consumerId);
			return {};
		});

		socket.once('disconnect', () => {
			release(socket.id);
		});
	});
}

async function authorizeSfuVoiceChannel(
	socket: AuthenticatedSocket,
	channelId: string,
): Promise<boolean> {
	const required = Permissions.VIEW_CHANNELS | Permissions.CONNECT_VOICE;

	if (!await authorizeSocketChannel(socket, channelId, required)) {
		return false;
	}

	const location = await db.query.channels.findFirst({
		columns: { workspaceId: true, type: true },
		where: eq(channels.id, channelId),
	});

	if (!location || location.type !== 'voice') {
		return false;
	}

	return db.transaction(async (transaction) => {
		await lockWorkspaceForAuthorization(
			transaction,
			location.workspaceId,
			'share',
		);

		const authorization = await getChannelAuthorizationFromStore(
			transaction,
			socket.userId!,
			channelId,
		);

		if (
			!socket.connected
			|| authorization?.workspaceId !== location.workspaceId
			|| !isVisibleChannelAuthorization(authorization)
			|| (authorization.permissions & required) !== required
		) {
			return false;
		}

		const room = `channel:${channelId}`;

		if (!socket.rooms.has(room)) {
			await socket.join(room);
		}

		return socket.connected && socket.rooms.has(room);
	});
}
