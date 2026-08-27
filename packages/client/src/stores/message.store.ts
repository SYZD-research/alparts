import { create } from 'zustand';
import { MAX_MESSAGE_LENGTH, type Attachment, type Message, type Reaction, type SignedMessageEnvelope } from '@alparts/shared';
import { api, ApiError } from '../services/api';
import {
  decryptMessage,
  encryptMessage,
  ensureChannelKey,
  getActiveDevice,
  getChannelKeyForVersion,
  signMessageEnvelope,
  verifyMessageSignature,
} from '../services/crypto.service';
import { retryFixedRequest } from '../services/fixed-request-retry';
import { mergeMessageEvents, projectMessageEvents, type ProjectedMessage } from './message-projector';

interface MessageState {
  eventsByChannel: Record<string, Message[]>;
  messagesByChannel: Record<string, ProjectedMessage[]>;
  isLoading: boolean;
  loadingByChannel: Record<string, boolean>;
  loadingMoreByChannel: Record<string, boolean>;
  hasMore: Record<string, boolean>;
  cursors: Record<string, string | null>;
  securityErrors: Record<string, string | null>;
  operationErrors: Record<string, string | null>;
  replyTargets: Record<string, ProjectedMessage | null>;
  editTargets: Record<string, ProjectedMessage | null>;
  loadMessages: (channelId: string) => Promise<void>;
  loadMoreMessages: (channelId: string) => Promise<void>;
  loadMessageThroughHistory: (channelId: string, messageId: string, maxPages?: number) => Promise<boolean>;
  sendMessage: (
    channelId: string,
    content: string,
    refMessageId?: string,
    idempotencyKey?: string,
    allowEmpty?: boolean,
  ) => Promise<Message>;
  addMessage: (channelId: string, message: Message) => void;
  applyAttachment: (channelId: string, attachment: Attachment) => void;
  replaceMessage: (channelId: string, message: Message) => void;
  editMessage: (messageId: string, channelId: string, content: string) => Promise<void>;
  deleteMessage: (messageId: string, channelId: string) => Promise<void>;
  removeMessage: (messageId: string, channelId: string) => void;
  applyReactionUpdate: (channelId: string, messageId: string, reactions: Reaction[]) => void;
  applyPinUpdate: (channelId: string, messageId: string, pinned: boolean) => void;
  toggleReaction: (messageId: string, emoji: string, channelId: string, userId: string) => Promise<void>;
  pinMessage: (messageId: string, channelId: string) => Promise<void>;
  decryptMessages: (channelId: string) => Promise<void>;
  setReplyTarget: (channelId: string, message: ProjectedMessage | null) => void;
  setEditTarget: (channelId: string, message: ProjectedMessage | null) => void;
  clearOperationError: (channelId: string) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

let messageStoreGeneration = 0;
const loadVersions = new Map<string, number>();
const initialLoadPromises = new Map<string, Promise<void>>();
const channelEpochs = new Map<string, number>();

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function nextLoadVersion(channelId: string): number {
  const version = (loadVersions.get(channelId) || 0) + 1;
  loadVersions.set(channelId, version);
  return version;
}

function currentChannelEpoch(channelId: string): number {
  return channelEpochs.get(channelId) || 0;
}

function isMessageContextCurrent(channelId: string, generation: number, channelEpoch: number): boolean {
  return generation === messageStoreGeneration && channelEpoch === currentChannelEpoch(channelId);
}

function channelUpdate(state: MessageState, channelId: string, events: Message[]) {
  const merged = mergeMessageEvents(events);
  return {
    eventsByChannel: { ...state.eventsByChannel, [channelId]: merged },
    messagesByChannel: { ...state.messagesByChannel, [channelId]: projectMessageEvents(merged) },
  };
}

function isTransientSendError(error: unknown): boolean {
  return error instanceof TypeError || (error instanceof ApiError && (
    error.status === 408
    || error.status === 425
    || error.status === 429
    || (error.status >= 500 && error.status <= 599)
  ));
}

async function retrySameEncryptedEnvelope<TRequest, TResponse>(
  request: TRequest,
  operation: (fixedRequest: TRequest) => Promise<TResponse>,
  generation: number,
  channelId: string,
  channelEpoch: number,
): Promise<TResponse> {
  return retryFixedRequest(request, operation, isTransientSendError, {
    attempts: 3,
    baseDelayMs: 250,
    isCurrent: () => isMessageContextCurrent(channelId, generation, channelEpoch),
    staleError: () => new Error('チャンネルの認可状態が変更されました'),
  });
}

/**
 * A REST response is still untrusted network data. Before attaching locally
 * known plaintext or setting the projector's verified marker, require every
 * signed field (and the signature itself) to be the exact envelope that this
 * device submitted. Server-assigned display metadata is deliberately excluded.
 */
export function matchesLocallySignedMessageResponse(
  event: Message,
  expected: SignedMessageEnvelope,
  expectedSignature: string,
): boolean {
  return event.type === expected.type
    && event.channelId === expected.channelId
    && event.authorId === expected.authorId
    && event.author?.id === expected.authorId
    && event.deviceId === expected.deviceId
    && event.keyVersion === expected.keyVersion
    && event.idempotencyKey === expected.idempotencyKey
    && event.refMessageId === expected.refMessageId
    && event.broadcastMention === expected.broadcastMention
    && event.encryptedContent === expected.encryptedContent
    && event.contentNonce === expected.contentNonce
    && event.signature === expectedSignature;
}

function requireLocallySignedMessageResponse(
  event: Message,
  expected: SignedMessageEnvelope,
  expectedSignature: string,
): Message {
  if (!matchesLocallySignedMessageResponse(event, expected, expectedSignature)) {
    throw new Error('Server returned a message event that does not match the signed request');
  }
  return { ...event, cryptoVerified: true } as Message;
}

export const useMessageStore = create<MessageState>((set, get) => ({
  eventsByChannel: {},
  messagesByChannel: {},
  isLoading: false,
  loadingByChannel: {},
  loadingMoreByChannel: {},
  hasMore: {},
  cursors: {},
  securityErrors: {},
  operationErrors: {},
  replyTargets: {},
  editTargets: {},

  loadMessages: async (channelId) => {
    const existing = initialLoadPromises.get(channelId);
    if (existing) return existing;
    const task = (async () => {
      const generation = messageStoreGeneration;
      const channelEpoch = currentChannelEpoch(channelId);
      const loadVersion = nextLoadVersion(channelId);
      set((state) => ({
        isLoading: true,
        loadingByChannel: { ...state.loadingByChannel, [channelId]: true },
      }));
      try {
        await ensureChannelKey(channelId);
        const result = await api.getMessages(channelId);
        if (!isMessageContextCurrent(channelId, generation, channelEpoch) || loadVersions.get(channelId) !== loadVersion) return;
        set((state) => ({
          ...channelUpdate(state, channelId, mergeMessageEvents(state.eventsByChannel[channelId] || [], result.data)),
          hasMore: { ...state.hasMore, [channelId]: result.hasMore },
          cursors: { ...state.cursors, [channelId]: result.cursor },
          securityErrors: { ...state.securityErrors, [channelId]: null },
          loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
          isLoading: false,
        }));
        await get().decryptMessages(channelId);
      } catch (error) {
        if (!isMessageContextCurrent(channelId, generation, channelEpoch) || loadVersions.get(channelId) !== loadVersion) return;
        set((state) => ({
          isLoading: false,
          loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
          securityErrors: { ...state.securityErrors, [channelId]: errorMessage(error, 'Secure channel initialization failed') },
        }));
      }
    })();
    initialLoadPromises.set(channelId, task);
    try {
      await task;
    } finally {
      if (initialLoadPromises.get(channelId) === task) initialLoadPromises.delete(channelId);
    }
  },

  loadMoreMessages: async (channelId) => {
    const state = get();
    const cursor = state.cursors[channelId];
    if (!cursor || !state.hasMore[channelId] || state.loadingMoreByChannel[channelId]) return;
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((current) => ({ loadingMoreByChannel: { ...current.loadingMoreByChannel, [channelId]: true } }));
    try {
      const result = await api.getMessages(channelId, cursor);
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
      set((current) => ({
        ...channelUpdate(current, channelId, mergeMessageEvents(current.eventsByChannel[channelId] || [], result.data)),
        hasMore: { ...current.hasMore, [channelId]: result.hasMore },
        cursors: { ...current.cursors, [channelId]: result.cursor },
      }));
      await get().decryptMessages(channelId);
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((current) => ({ operationErrors: { ...current.operationErrors, [channelId]: errorMessage(error, '過去のメッセージを読み込めませんでした') } }));
      }
    } finally {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((current) => ({ loadingMoreByChannel: { ...current.loadingMoreByChannel, [channelId]: false } }));
      }
    }
  },

  loadMessageThroughHistory: async (channelId, messageId, maxPages = 20) => {
    const containsTarget = () => (get().eventsByChannel[channelId] || []).some((event) => event.id === messageId);
    if (containsTarget()) return true;
    await get().loadMessages(channelId);
    if (containsTarget()) return true;
    for (let page = 0; page < maxPages && get().hasMore[channelId]; page += 1) {
      const previousCursor = get().cursors[channelId];
      await get().loadMoreMessages(channelId);
      if (containsTarget()) return true;
      if (!get().cursors[channelId] || get().cursors[channelId] === previousCursor) break;
    }
    return containsTarget();
  },

  sendMessage: async (channelId, content, refMessageId, fixedIdempotencyKey, allowEmpty = false) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      if ((!content && !allowEmpty) || content.length > MAX_MESSAGE_LENGTH || new TextEncoder().encode(content).length > MAX_MESSAGE_LENGTH * 4) {
        throw new Error('Message is too long');
      }
      const device = getActiveDevice();
      const channelKey = await ensureChannelKey(channelId);
      const idempotencyKey = fixedIdempotencyKey || crypto.randomUUID();
      const broadcastMention = containsBroadcastMention(content);
      const unsigned = {
        type: 'message' as const,
        channelId,
        authorId: device.userId,
        deviceId: device.deviceId,
        keyVersion: channelKey.version,
        idempotencyKey,
        refMessageId: refMessageId ?? null,
        broadcastMention,
      };
      const encrypted = await encryptMessage(content, channelKey.key, unsigned);
      const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent: encrypted.encrypted, contentNonce: encrypted.nonce };
      const signature = await signMessageEnvelope(envelope);
      const request = {
        encryptedContent: envelope.encryptedContent,
        contentNonce: envelope.contentNonce,
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
        broadcastMention,
        refMessageId: refMessageId || undefined,
      };
      // Network retries reuse the exact authenticated envelope. Re-encrypting
      // under the same idempotency key would correctly be rejected as a
      // different event if the first response was lost.
      const message = await retrySameEncryptedEnvelope(
        request,
        (fixedRequest) => api.sendMessage(channelId, fixedRequest),
        generation,
        channelId,
        channelEpoch,
      );
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) throw new Error('チャンネルの認可が変更されたため送信結果を破棄しました');
      const decryptedMessage = {
        ...requireLocallySignedMessageResponse(message, envelope, signature),
        content,
      } as Message;
      get().addMessage(channelId, decryptedMessage);
      return decryptedMessage;
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, 'メッセージを送信できませんでした') } }));
      }
      throw error;
    }
  },

  addMessage: (channelId, message) => {
    set((state) => channelUpdate(state, channelId, mergeMessageEvents(state.eventsByChannel[channelId] || [], [message])));
    if (message.type === 'message' || message.type === 'edit' || message.type === 'delete') void get().decryptMessages(channelId);
  },

  applyAttachment: (channelId, attachment) => {
    set((state) => {
      let found = false;
      const events = (state.eventsByChannel[channelId] || []).map((event) => {
        if (event.id !== attachment.messageId || event.type !== 'message') return event;
        found = true;
        const attachments = [...(event.attachments || []).filter((item) => item.id !== attachment.id), attachment]
          .sort((left, right) => left.createdAt < right.createdAt
            ? -1
            : left.createdAt > right.createdAt
              ? 1
              : left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
        return { ...event, attachments };
      });
      return found ? channelUpdate(state, channelId, events) : state;
    });
  },

  replaceMessage: (channelId, message) => {
    get().addMessage(channelId, message);
  },

  editMessage: async (messageId, channelId, content) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      const device = getActiveDevice();
      const channelKey = await ensureChannelKey(channelId);
      const idempotencyKey = crypto.randomUUID();
      const broadcastMention = containsBroadcastMention(content);
      const unsigned = {
        type: 'edit' as const,
        channelId,
        authorId: device.userId,
        deviceId: device.deviceId,
        keyVersion: channelKey.version,
        idempotencyKey,
        refMessageId: messageId,
        broadcastMention,
      };
      const encrypted = await encryptMessage(content, channelKey.key, unsigned);
      const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent: encrypted.encrypted, contentNonce: encrypted.nonce };
      const signature = await signMessageEnvelope(envelope);
      const request = {
        encryptedContent: envelope.encryptedContent,
        contentNonce: envelope.contentNonce,
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
        broadcastMention,
      };
      const event = await retrySameEncryptedEnvelope(
        request,
        (fixedRequest) => api.editMessage(messageId, fixedRequest),
        generation,
        channelId,
        channelEpoch,
      );
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) throw new Error('チャンネルの認可が変更されたため編集結果を破棄しました');
      get().addMessage(channelId, {
        ...requireLocallySignedMessageResponse(event, envelope, signature),
        content,
      } as Message);
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, 'メッセージを編集できませんでした') } }));
      }
      throw error;
    }
  },

  deleteMessage: async (messageId, channelId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      const device = getActiveDevice();
      const channelKey = await ensureChannelKey(channelId);
      const envelope: SignedMessageEnvelope = {
        type: 'delete',
        channelId,
        authorId: device.userId,
        deviceId: device.deviceId,
        keyVersion: channelKey.version,
        idempotencyKey: crypto.randomUUID(),
        refMessageId: messageId,
        broadcastMention: false,
        encryptedContent: '',
        contentNonce: '',
      };
      const signature = await signMessageEnvelope(envelope);
      const request = {
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
      };
      const result = await retrySameEncryptedEnvelope(
        request,
        (fixedRequest) => api.deleteMessage(messageId, fixedRequest),
        generation,
        channelId,
        channelEpoch,
      );
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) throw new Error('チャンネルの認可が変更されたため削除結果を破棄しました');
      if (!result?.event) throw new Error('署名済み削除イベントが返されませんでした');
      if (result.messageId !== messageId || result.channelId !== channelId) {
        throw new Error('Server returned a delete result for a different message');
      }
      get().addMessage(channelId, requireLocallySignedMessageResponse(result.event, envelope, signature));
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, 'メッセージを削除できませんでした') } }));
      }
      throw error;
    }
  },

  removeMessage: (messageId, channelId) => {
    set((state) => ({
      securityErrors: {
        ...state.securityErrors,
        [channelId]: `署名済み削除イベントを確認できませんでした (${messageId})`,
      },
    }));
  },

  applyReactionUpdate: (channelId, messageId, reactions) => {
    set((state) => {
      const events = (state.eventsByChannel[channelId] || [])
        .filter((event) => !(event.type === 'reaction' && event.refMessageId === messageId))
        .map((event) => event.id === messageId ? { ...event, reactions } : event);
      return channelUpdate(state, channelId, events);
    });
  },

  applyPinUpdate: (channelId, messageId, pinned) => {
    set((state) => {
      const events = (state.eventsByChannel[channelId] || []).map((event) => (
        event.id === messageId ? { ...event, isPinned: pinned } : event
      ));
      return channelUpdate(state, channelId, events);
    });
  },

  toggleReaction: async (messageId, emoji, channelId, _userId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      const result = await api.toggleReaction(messageId, emoji);
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
      get().applyReactionUpdate(channelId, messageId, result.reactions || []);
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, 'リアクションを更新できませんでした') } }));
      }
      throw error;
    }
  },

  pinMessage: async (messageId, channelId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      const result = await api.pinMessage(messageId);
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
      get().applyPinUpdate(channelId, messageId, Boolean(result.pinned));
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, 'ピンを更新できませんでした') } }));
      }
      throw error;
    }
  },

  decryptMessages: async (channelId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    try {
      const directory = await api.getChannelDeviceDirectory(channelId);
      const identities = new Map(directory.map((device) => [
        device.deviceId,
        { userId: device.userId, identityKey: device.identityKey },
      ]));
      const snapshot = get().eventsByChannel[channelId] || [];
      const decrypted = await Promise.all(snapshot.map(async (message): Promise<Message | null> => {
        if (message.type !== 'message' && message.type !== 'edit' && message.type !== 'delete') return message;
        if (!message.deviceId || !message.signature || (message.type !== 'delete' && !message.contentNonce)) {
          if (message.type !== 'message') return null;
          return { ...message, content: '[未検証の旧形式メッセージ]' };
        }
        const identity = identities.get(message.deviceId);
        const envelope: SignedMessageEnvelope = {
          type: message.type,
          channelId: message.channelId,
          authorId: message.authorId,
          deviceId: message.deviceId,
          keyVersion: message.keyVersion,
          idempotencyKey: message.idempotencyKey,
          refMessageId: message.refMessageId,
          broadcastMention: message.broadcastMention ?? null,
          encryptedContent: message.encryptedContent,
          contentNonce: message.contentNonce,
        };
        const invalidSignature = (
          !identity
          || identity.userId !== message.authorId
          || message.author.id !== message.authorId
          || !await verifyMessageSignature(envelope, message.signature, identity.identityKey)
        );
        if (invalidSignature) {
          if (message.type !== 'message') return null;
          return { ...message, content: '[署名検証に失敗したメッセージ]' };
        }
        if (message.type === 'delete') return { ...message, cryptoVerified: true } as Message;
        const key = await getChannelKeyForVersion(channelId, message.keyVersion);
        if (!key) return { ...message, content: '[復号鍵を利用できません]' };
        try {
          return { ...message, content: await decryptMessage(envelope, key), cryptoVerified: true } as Message;
        } catch {
          return { ...message, content: '[改ざんを検出しました]' };
        }
      }));
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
      const quarantinedIds = new Set(snapshot
        .filter((_event, index) => decrypted[index] === null)
        .map((event) => event.id));
      const decryptedById = new Map(decrypted.flatMap((event) => event ? [[event.id, event] as const] : []));
      set((state) => {
        const current = state.eventsByChannel[channelId] || [];
        const merged = current
          .filter((event) => !quarantinedIds.has(event.id))
          .map((event) => decryptedById.get(event.id) || event);
        const next = channelUpdate(state, channelId, merged);
        return quarantinedIds.size === 0 ? next : {
          ...next,
          securityErrors: {
            ...state.securityErrors,
            [channelId]: `${quarantinedIds.size}件の未検証変更イベントを隔離しました`,
          },
        };
      });
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ securityErrors: { ...state.securityErrors, [channelId]: errorMessage(error, 'メッセージを安全に検証できませんでした') } }));
      }
    }
  },

  setReplyTarget: (channelId, message) => set((state) => ({
    replyTargets: { ...state.replyTargets, [channelId]: message },
    editTargets: { ...state.editTargets, [channelId]: null },
  })),

  setEditTarget: (channelId, message) => set((state) => ({
    editTargets: { ...state.editTargets, [channelId]: message },
    replyTargets: { ...state.replyTargets, [channelId]: null },
  })),

  clearOperationError: (channelId) => set((state) => ({
    operationErrors: { ...state.operationErrors, [channelId]: null },
  })),

  clearChannel: (channelId) => {
    channelEpochs.set(channelId, currentChannelEpoch(channelId) + 1);
    nextLoadVersion(channelId);
    initialLoadPromises.delete(channelId);
    set((state) => {
      const eventsByChannel = withoutChannel(state.eventsByChannel, channelId);
      const messagesByChannel = withoutChannel(state.messagesByChannel, channelId);
      const loadingByChannel = withoutChannel(state.loadingByChannel, channelId);
      return {
        eventsByChannel,
        messagesByChannel,
        loadingByChannel,
        loadingMoreByChannel: withoutChannel(state.loadingMoreByChannel, channelId),
        hasMore: withoutChannel(state.hasMore, channelId),
        cursors: withoutChannel(state.cursors, channelId),
        securityErrors: withoutChannel(state.securityErrors, channelId),
        operationErrors: withoutChannel(state.operationErrors, channelId),
        replyTargets: withoutChannel(state.replyTargets, channelId),
        editTargets: withoutChannel(state.editTargets, channelId),
        isLoading: Object.values(loadingByChannel).some(Boolean),
      };
    });
  },

  reset: () => {
    messageStoreGeneration += 1;
    loadVersions.clear();
    initialLoadPromises.clear();
    channelEpochs.clear();
    set({
      eventsByChannel: {},
      messagesByChannel: {},
      isLoading: false,
      loadingByChannel: {},
      loadingMoreByChannel: {},
      hasMore: {},
      cursors: {},
      securityErrors: {},
      operationErrors: {},
      replyTargets: {},
      editTargets: {},
    });
  },
}));

export function containsBroadcastMention(content: string): boolean {
  return /(^|[^\p{L}\p{N}_])@(everyone|here)(?=$|[^\p{L}\p{N}_])/iu.test(content.normalize('NFKC'));
}

function withoutChannel<T>(record: Record<string, T>, channelId: string): Record<string, T> {
  if (!(channelId in record)) return record;
  const next = { ...record };
  delete next[channelId];
  return next;
}
