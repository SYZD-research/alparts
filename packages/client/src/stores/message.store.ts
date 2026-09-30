import { create } from 'zustand';
import {
  MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE,
  MAX_MESSAGE_LENGTH,
  type Attachment,
  type Message,
  type Reaction,
  type SignedMessageEnvelope,
} from '@alparts/shared';
import { api, ApiError } from '../services/api';
import {
  decryptMessage,
  encryptMessage,
  ensureChannelKey,
  getActiveDevice,
  getChannelKeysForVersions,
  isChannelKeyActivationPendingError,
  isChannelKeyDeliveryPendingError,
  signMessageEnvelope,
  startChannelWithoutHistory as establishFreshChannel,
  verifyMessageSignature,
} from '../services/crypto.service';
import { retryFixedRequest } from '../services/fixed-request-retry';
import { CoalescedChannelWorker } from '../services/coalesced-channel-worker';
import { uniqueValueChunks } from '../services/coalesced-value-loader';
import {
  getMessageCryptoVerificationState,
  hasAuthenticatedEnvelopeConflict,
  isMessageKeyUnavailable,
  markMessageCryptoVerification,
  markMessageKeyUnavailable,
  mergeMessageEvents,
  projectOrderedMessageEvents,
  retryMessageKeyVerification,
  type ProjectedMessage,
} from './message-projector';
import { useChannelStore } from './channel.store';
import { encodeForumPostContent } from '../services/forum-post-model';
import type { ForumPostState } from '@alparts/shared';

export const MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL = 1_000;
export const MAX_RESIDENT_MESSAGE_EVENTS_TOTAL = 5_000;
export const MAX_RESIDENT_MESSAGE_CHANNELS = 32;
const MAX_PARALLEL_MESSAGE_CRYPTO = 64;

interface MessageState {
  eventsByChannel: Record<string, Message[]>;
  messagesByChannel: Record<string, ProjectedMessage[]>;
  isLoading: boolean;
  loadingByChannel: Record<string, boolean>;
  loadingMoreByChannel: Record<string, boolean>;
  hasMore: Record<string, boolean>;
  cursors: Record<string, string | null>;
  securityErrors: Record<string, string | null>;
  channelKeyPending: Record<string, string | null>;
  channelRecoveryPending: Record<string, boolean>;
  operationErrors: Record<string, string | null>;
  replyTargets: Record<string, ProjectedMessage | null>;
  editTargets: Record<string, ProjectedMessage | null>;
  loadMessages: (channelId: string) => Promise<void>;
  loadMoreMessages: (channelId: string) => Promise<void>;
  loadMessageThroughHistory: (channelId: string, messageId: string, maxPages?: number) => Promise<boolean>;
  reconcileChannelKey: (channelId: string) => Promise<boolean>;
  retryChannelPreparation: (channelId: string) => Promise<boolean>;
  startChannelWithoutHistory: (channelId: string) => Promise<void>;
  sendMessage: (
    channelId: string,
    content: string,
    refMessageId?: string,
    idempotencyKey?: string,
    allowEmpty?: boolean,
    mentionedUserIds?: string[],
    postId?: string,
  ) => Promise<Message>;
  createForumPost: (
    channelId: string,
    post: { title: string; body: string; tagIds: string[]; mentionedUserIds: string[] },
  ) => Promise<{ message: Message; state: Omit<ForumPostState, 'unread'> }>;
  addMessage: (channelId: string, message: Message) => void;
  addMessages: (channelId: string, messages: Message[]) => void;
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
  retryUnavailableMessages: (channelId: string) => void;
  setReplyTarget: (channelId: string, message: ProjectedMessage | null) => void;
  setEditTarget: (channelId: string, message: ProjectedMessage | null) => void;
  clearOperationError: (channelId: string) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

let messageStoreGeneration = 0;
const loadVersions = new Map<string, number>();
const initialLoadPromises = new Map<string, Promise<void>>();
const keyReconciliationPromises = new Map<string, Promise<boolean>>();
const channelEpochs = new Map<string, number>();
const residentChannelOrder = new Map<string, true>();
const messageDecryptWorkers = new CoalescedChannelWorker(MAX_RESIDENT_MESSAGE_CHANNELS);

function cryptoVerificationState(message: Message): boolean | undefined {
  return getMessageCryptoVerificationState(message);
}

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
  const ordered = mergeMessageEvents(events);
  const merged = ordered.length > MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL
    ? mergeMessageEvents(ordered.slice(-MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL)) : ordered;
  const envelopeConflict = merged.some(hasAuthenticatedEnvelopeConflict);
  residentChannelOrder.delete(channelId);
  residentChannelOrder.set(channelId, true);
  const eventsByChannel = { ...state.eventsByChannel, [channelId]: merged };
  const messagesByChannel = { ...state.messagesByChannel, [channelId]: projectOrderedMessageEvents(merged) };
  const evicted: string[] = [];
  let residentEvents = Object.values(eventsByChannel).reduce((total, entries) => total + entries.length, 0);
  while (
    Object.keys(eventsByChannel).length > MAX_RESIDENT_MESSAGE_CHANNELS
    || residentEvents > MAX_RESIDENT_MESSAGE_EVENTS_TOTAL
  ) {
    const activeChannelId = useChannelStore.getState().activeChannelId;
    const victim = [...residentChannelOrder.keys()].find((candidate) => candidate !== channelId && candidate !== activeChannelId);
    if (!victim) break;
    residentChannelOrder.delete(victim);
    evicted.push(victim);
    residentEvents -= eventsByChannel[victim]?.length ?? 0;
    delete eventsByChannel[victim];
    delete messagesByChannel[victim];
    channelEpochs.set(victim, currentChannelEpoch(victim) + 1);
    nextLoadVersion(victim);
    initialLoadPromises.delete(victim);
    messageDecryptWorkers.cancel(victim);
  }
  if (evicted.length > 0) {
    const omitEvicted = <T>(record: Record<string, T>) => {
      let next = record;
      for (const victim of evicted) next = withoutChannel(next, victim);
      return next;
    };
    const loadingByChannel = omitEvicted(state.loadingByChannel);
    return {
      eventsByChannel,
      messagesByChannel,
      loadingByChannel,
      loadingMoreByChannel: omitEvicted(state.loadingMoreByChannel),
      hasMore: omitEvicted(state.hasMore),
      cursors: omitEvicted(state.cursors),
      securityErrors: envelopeConflict
        ? {
            ...omitEvicted(state.securityErrors),
            [channelId]: '安全のため、このチャンネルの履歴の読み込みを停止しました',
          }
        : omitEvicted(state.securityErrors),
      channelKeyPending: omitEvicted(state.channelKeyPending),
      channelRecoveryPending: omitEvicted(state.channelRecoveryPending),
      operationErrors: omitEvicted(state.operationErrors),
      replyTargets: omitEvicted(state.replyTargets),
      editTargets: omitEvicted(state.editTargets),
      isLoading: Object.values(loadingByChannel).some(Boolean),
    };
  }
  const update: Partial<MessageState> = {
    eventsByChannel,
    messagesByChannel,
  };
  if (envelopeConflict) {
    update.securityErrors = {
      ...state.securityErrors,
      [channelId]: '安全のため、このチャンネルの履歴の読み込みを停止しました',
    };
  }
  return update;
}

/** Forum channels sign every event with its post (v4); the type, not the payload, decides. */
export function isForumChannel(channelId: string): boolean {
  return useChannelStore.getState().channels.find((channel) => channel.id === channelId)?.type === 'forum';
}

/** The post a verified forum message belongs to: its own id if it started the post. */
function forumPostIdOf(state: MessageState, channelId: string, messageId: string): string {
  const base = (state.eventsByChannel[channelId] || []).find((event) => event.id === messageId && event.type === 'message');
  if (!base || getMessageCryptoVerificationState(base) !== true) {
    throw new Error('メッセージを確認できませんでした。再読み込みしてお試しください。');
  }
  return base.postId ?? base.id;
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
    && (expected.postId === undefined || (event.postId ?? null) === expected.postId)
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
  return markMessageCryptoVerification(event, true);
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
  channelKeyPending: {},
  channelRecoveryPending: {},
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
        let keyPending: string | null = null;
        try {
          await ensureChannelKey(channelId);
        } catch (error) {
          if (!isChannelKeyActivationPendingError(error)) throw error;
          // A pending epoch is an expected availability state. History remains
          // readable with previously activated epochs, while writes continue
          // to fail closed until every required recipient acknowledges it.
          keyPending = error.message;
        }
        const result = await api.getMessages(channelId);
        if (!isMessageContextCurrent(channelId, generation, channelEpoch) || loadVersions.get(channelId) !== loadVersion) return;
        set((state) => ({
          ...channelUpdate(state, channelId, mergeMessageEvents(state.eventsByChannel[channelId] || [], result.data)),
          hasMore: { ...state.hasMore, [channelId]: result.hasMore },
          cursors: { ...state.cursors, [channelId]: result.cursor },
          securityErrors: { ...state.securityErrors, [channelId]: null },
          channelKeyPending: { ...state.channelKeyPending, [channelId]: keyPending },
          channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: false },
          loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
          isLoading: Object.entries(state.loadingByChannel).some(([id, loading]) => id !== channelId && loading),
        }));
        await get().decryptMessages(channelId);
      } catch (error) {
        if (!isMessageContextCurrent(channelId, generation, channelEpoch) || loadVersions.get(channelId) !== loadVersion) return;
        const recoveryPending = isChannelKeyDeliveryPendingError(error);
        set((state) => ({
          isLoading: Object.entries(state.loadingByChannel).some(([id, loading]) => id !== channelId && loading),
          loadingByChannel: { ...state.loadingByChannel, [channelId]: false },
          securityErrors: {
            ...state.securityErrors,
            [channelId]: recoveryPending ? null : errorMessage(error, 'Secure channel initialization failed'),
          },
          channelKeyPending: {
            ...state.channelKeyPending,
            [channelId]: recoveryPending ? error.message : null,
          },
          channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: recoveryPending },
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
    if (!cursor || !state.hasMore[channelId] || state.loadingMoreByChannel[channelId] || state.loadingByChannel[channelId]) return;
    if ((state.eventsByChannel[channelId]?.length ?? 0) >= MAX_RESIDENT_MESSAGE_EVENTS_PER_CHANNEL) {
      set((current) => ({
        hasMore: { ...current.hasMore, [channelId]: false },
        cursors: { ...current.cursors, [channelId]: null },
        operationErrors: {
          ...current.operationErrors,
          [channelId]: 'これ以上の履歴を表示できません。再読み込みしてお試しください。',
        },
      }));
      return;
    }
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    const loadVersion = loadVersions.get(channelId);
    set((current) => ({ loadingMoreByChannel: { ...current.loadingMoreByChannel, [channelId]: true } }));
    try {
      const result = await api.getMessages(channelId, cursor);
      if (!isMessageContextCurrent(channelId, generation, channelEpoch) || loadVersions.get(channelId) !== loadVersion) return;
      set((current) => ({
        ...channelUpdate(current, channelId, mergeMessageEvents(current.eventsByChannel[channelId] || [], result.data)),
        hasMore: { ...current.hasMore, [channelId]: result.hasMore },
        cursors: { ...current.cursors, [channelId]: result.cursor },
      }));
      await get().decryptMessages(channelId);
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch) && loadVersions.get(channelId) === loadVersion) {
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

  reconcileChannelKey: async (channelId) => {
    const existing = keyReconciliationPromises.get(channelId);
    if (existing) return existing;
    const reconciliation = (async () => {
      const generation = messageStoreGeneration;
      const channelEpoch = currentChannelEpoch(channelId);
      try {
        await ensureChannelKey(channelId);
        if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return false;
        set((state) => ({
          channelKeyPending: { ...state.channelKeyPending, [channelId]: null },
          channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: false },
          securityErrors: { ...state.securityErrors, [channelId]: null },
        }));
        get().retryUnavailableMessages(channelId);
        return true;
      } catch (error) {
        if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return false;
        if (isChannelKeyActivationPendingError(error)) {
          set((state) => ({
            channelKeyPending: { ...state.channelKeyPending, [channelId]: error.message },
            channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: false },
            securityErrors: { ...state.securityErrors, [channelId]: null },
          }));
        } else if (isChannelKeyDeliveryPendingError(error)) {
          set((state) => ({
            channelKeyPending: { ...state.channelKeyPending, [channelId]: error.message },
            channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: true },
            securityErrors: { ...state.securityErrors, [channelId]: null },
          }));
        } else {
          set((state) => ({
            channelKeyPending: { ...state.channelKeyPending, [channelId]: null },
            channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: false },
            securityErrors: {
              ...state.securityErrors,
              [channelId]: errorMessage(error, 'Secure channel initialization failed'),
            },
          }));
        }
        return false;
      }
    })();
    keyReconciliationPromises.set(channelId, reconciliation);
    try {
      return await reconciliation;
    } finally {
      if (keyReconciliationPromises.get(channelId) === reconciliation) {
        keyReconciliationPromises.delete(channelId);
      }
    }
  },

  retryChannelPreparation: async (channelId) => {
    const reloadMessages = Boolean(get().channelRecoveryPending[channelId]);
    if (!await get().reconcileChannelKey(channelId)) return false;
    if (reloadMessages) await get().loadMessages(channelId);
    return true;
  },

  startChannelWithoutHistory: async (channelId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    await establishFreshChannel(channelId);
    if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
    set((state) => ({
      securityErrors: { ...state.securityErrors, [channelId]: null },
      channelKeyPending: { ...state.channelKeyPending, [channelId]: null },
      channelRecoveryPending: { ...state.channelRecoveryPending, [channelId]: false },
      operationErrors: { ...state.operationErrors, [channelId]: null },
    }));
    get().retryUnavailableMessages(channelId);
    await get().loadMessages(channelId);
  },

  sendMessage: async (channelId, content, refMessageId, fixedIdempotencyKey, allowEmpty = false, mentionedUserIds = [], postId) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      if ((!content && !allowEmpty) || content.length > MAX_MESSAGE_LENGTH || new TextEncoder().encode(content).length > MAX_MESSAGE_LENGTH * 4) {
        throw new Error('Message is too long');
      }
      // New posts go through createForumPost; everything else in a forum is a reply.
      const forum = isForumChannel(channelId);
      if (forum !== Boolean(postId)) throw new Error('メッセージを送信できませんでした');
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
        ...(forum ? { postId: postId! } : {}),
      };
      const encrypted = await encryptMessage(content, channelKey.key, unsigned);
      const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent: encrypted.encrypted, contentNonce: encrypted.nonce };
      const signature = await signMessageEnvelope(envelope);
      const notificationRecipientIds = [...new Set(mentionedUserIds)]
        .sort()
        .slice(0, MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE);
      const request = {
        encryptedContent: envelope.encryptedContent,
        contentNonce: envelope.contentNonce,
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
        broadcastMention,
        ...(notificationRecipientIds.length ? { mentionedUserIds: notificationRecipientIds } : {}),
        refMessageId: refMessageId || undefined,
        ...(forum ? { postId } : {}),
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

  createForumPost: async (channelId, post) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: null } }));
    try {
      if (!isForumChannel(channelId)) throw new Error('投稿を作成できませんでした');
      const content = encodeForumPostContent({ title: post.title, body: post.body });
      const device = getActiveDevice();
      const channelKey = await ensureChannelKey(channelId);
      const broadcastMention = containsBroadcastMention(content);
      const unsigned = {
        type: 'message' as const,
        channelId,
        authorId: device.userId,
        deviceId: device.deviceId,
        keyVersion: channelKey.version,
        idempotencyKey: crypto.randomUUID(),
        refMessageId: null,
        broadcastMention,
        postId: null,
      };
      const encrypted = await encryptMessage(content, channelKey.key, unsigned);
      const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent: encrypted.encrypted, contentNonce: encrypted.nonce };
      const signature = await signMessageEnvelope(envelope);
      const mentionedUserIds = [...new Set(post.mentionedUserIds)].sort().slice(0, MAX_DIRECT_MENTION_RECIPIENTS_PER_MESSAGE);
      const request = {
        encryptedContent: envelope.encryptedContent,
        contentNonce: envelope.contentNonce,
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
        broadcastMention,
        ...(mentionedUserIds.length ? { mentionedUserIds } : {}),
        ...(post.tagIds.length ? { tagIds: post.tagIds } : {}),
      };
      const result = await retrySameEncryptedEnvelope(
        request,
        (fixedRequest) => api.createForumPost(channelId, fixedRequest),
        generation,
        channelId,
        channelEpoch,
      );
      if (!isMessageContextCurrent(channelId, generation, channelEpoch)) throw new Error('チャンネルの認可が変更されたため送信結果を破棄しました');
      const message = { ...requireLocallySignedMessageResponse(result.message, envelope, signature), content } as Message;
      if (result.state.postId !== message.id || result.state.channelId !== channelId) {
        throw new Error('Server returned a post state for a different post');
      }
      get().addMessage(channelId, message);
      return { message, state: result.state };
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        set((state) => ({ operationErrors: { ...state.operationErrors, [channelId]: errorMessage(error, '投稿を作成できませんでした') } }));
      }
      throw error;
    }
  },

  addMessage: (channelId, message) => get().addMessages(channelId, [message]),

  addMessages: (channelId, messages) => {
    const generation = messageStoreGeneration;
    const epoch = currentChannelEpoch(channelId);
    set((state) => channelUpdate(state, channelId, mergeMessageEvents(state.eventsByChannel[channelId] || [], messages)));
    if (messages.some((message) => message.type === 'message' || message.type === 'edit' || message.type === 'delete')) {
      void get().decryptMessages(channelId).catch((error) => {
        if (!isMessageContextCurrent(channelId, generation, epoch)) return;
        set((state) => ({
          securityErrors: {
            ...state.securityErrors,
            [channelId]: errorMessage(error, 'メッセージ検証の再同期が必要です'),
          },
        }));
      });
    }
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
      const postId = isForumChannel(channelId) ? forumPostIdOf(get(), channelId, messageId) : undefined;
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
        ...(postId ? { postId } : {}),
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
        ...(postId ? { postId } : {}),
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
      const postId = isForumChannel(channelId) ? forumPostIdOf(get(), channelId, messageId) : undefined;
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
        ...(postId ? { postId } : {}),
      };
      const signature = await signMessageEnvelope(envelope);
      const request = {
        deviceId: envelope.deviceId,
        keyVersion: envelope.keyVersion,
        idempotencyKey: envelope.idempotencyKey,
        signature,
        ...(postId ? { postId } : {}),
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
        [channelId]: 'メッセージの削除を確認できませんでした。再読み込みしてお試しください。',
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

  decryptMessages: (channelId) => messageDecryptWorkers.run(channelId, async (signal) => {
    const generation = messageStoreGeneration;
    const channelEpoch = currentChannelEpoch(channelId);
    let unverified: Message[] = [];
    const forumChannel = isForumChannel(channelId);
    try {
      const snapshot = get().eventsByChannel[channelId] || [];
      unverified = snapshot.filter((message) => (
        (message.type === 'message' || message.type === 'edit' || message.type === 'delete')
        && cryptoVerificationState(message) === undefined
      ));
      const keyVersions = unverified.flatMap((message) => (
        message.type === 'delete' ? [] : [message.keyVersion]
      ));
      const keysByVersion = new Map<number, CryptoKey | null>();
      for (const versions of uniqueValueChunks(keyVersions, 64)) {
        if (signal.aborted) throw signal.reason;
        try {
          const loaded = await getChannelKeysForVersions(channelId, versions, signal);
          for (const [version, key] of loaded) keysByVersion.set(version, key);
        } catch {
          if (signal.aborted) throw signal.reason;
          // A failed bounded lookup is terminal for this resident snapshot.
          // Explicit key-state reconciliation or a full reload re-enables it.
          for (const version of versions) keysByVersion.set(version, null);
        }
      }
      for (let offset = 0; offset < unverified.length; offset += MAX_PARALLEL_MESSAGE_CRYPTO) {
        if (signal.aborted) throw signal.reason;
        const batch = unverified.slice(offset, offset + MAX_PARALLEL_MESSAGE_CRYPTO);
        const requestedDeviceIds = [...new Set(batch.flatMap((message) => (
          message.deviceId ? [message.deviceId] : []
        )))];
        const directory = requestedDeviceIds.length === 0
          ? []
          : await api.getChannelDeviceDirectory(channelId, requestedDeviceIds, signal);
        const identities = new Map(directory.map((device) => [
          device.deviceId,
          { userId: device.userId, identityKey: device.identityKey },
        ]));
        const decrypted = await Promise.all(batch.map(async (message): Promise<Message | null> => {
          if (message.type !== 'message' && message.type !== 'edit' && message.type !== 'delete') return message;
          if (!message.deviceId || !message.signature || (message.type !== 'delete' && !message.contentNonce)) {
            if (message.type !== 'message') return null;
            return markMessageCryptoVerification({ ...message, content: '[表示できないメッセージ]' }, false);
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
            // The signed layout follows the channel type (the channel id is
            // signed), so a server cannot pick v3 or v4 by adding a field.
            ...(forumChannel ? { postId: message.postId ?? null } : {}),
          };
          const invalidSignature = (
            !identity
            || identity.userId !== message.authorId
            || message.author.id !== message.authorId
            || !await verifyMessageSignature(envelope, message.signature, identity.identityKey).catch(() => false)
          );
          if (invalidSignature) {
            if (message.type !== 'message') return null;
            return markMessageCryptoVerification({ ...message, content: '[メッセージを検証できませんでした]' }, false);
          }
          if (message.type === 'delete') return markMessageCryptoVerification(message, true);
          const key = keysByVersion.get(message.keyVersion) ?? null;
          if (!key) return markMessageKeyUnavailable(message);
          try {
            return markMessageCryptoVerification({ ...message, content: await decryptMessage(envelope, key) }, true);
          } catch {
            return markMessageCryptoVerification({ ...message, content: '[改ざんを検出しました]' }, false);
          }
        }));
        if (signal.aborted) throw signal.reason;
        if (!isMessageContextCurrent(channelId, generation, channelEpoch)) return;
        const quarantinedIds = new Set(batch
          .filter((_event, index) => decrypted[index] === null)
          .map((event) => event.id));
        const decryptedById = new Map(decrypted.flatMap((event) => event ? [[event.id, event] as const] : []));
        set((state) => {
          const current = state.eventsByChannel[channelId] || [];
          const merged = current
            .filter((event) => !quarantinedIds.has(event.id))
            .map((event) => {
              const decryptedEvent = decryptedById.get(event.id);
              if (!decryptedEvent) return event;
              // A conflicting duplicate may arrive while signature/AEAD work is
              // in flight. Merge the newer resident event last so an envelope
              // conflict remains sticky and newer server-owned aggregates win.
              return mergeMessageEvents([decryptedEvent], [event])[0];
            });
          const next = channelUpdate(state, channelId, merged);
          return quarantinedIds.size === 0 ? next : {
            ...next,
            securityErrors: {
              ...state.securityErrors,
              [channelId]: '安全を確認できない変更があるため、一部の更新を表示していません。',
            },
          };
        });
      }
    } catch (error) {
      if (isMessageContextCurrent(channelId, generation, channelEpoch)) {
        const unavailableIds = new Set(unverified.map((event) => event.id));
        set((state) => {
          // Directory, key, or other verification-dependency failures must
          // not be retried by every subsequent socket event. Terminalize only
          // the still-unverified snapshot; explicit key-state reconciliation
          // or a full channel reload clears the process-local marker.
          const events = (state.eventsByChannel[channelId] || []).map((event) => (
            unavailableIds.has(event.id) && cryptoVerificationState(event) === undefined
              ? markMessageKeyUnavailable(event)
              : event
          ));
          return {
            ...channelUpdate(state, channelId, events),
            securityErrors: {
              ...state.securityErrors,
              [channelId]: errorMessage(error, 'メッセージを安全に検証できませんでした'),
            },
          };
        });
      }
    }
  }),

  retryUnavailableMessages: (channelId) => {
    let changed = false;
    set((state) => {
      const events = (state.eventsByChannel[channelId] || []).map((event) => {
        if (!isMessageKeyUnavailable(event)) return event;
        changed = true;
        return retryMessageKeyVerification(event);
      });
      return changed ? channelUpdate(state, channelId, events) : state;
    });
    if (changed) void get().decryptMessages(channelId);
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
    keyReconciliationPromises.delete(channelId);
    residentChannelOrder.delete(channelId);
    messageDecryptWorkers.cancel(channelId);
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
        channelKeyPending: withoutChannel(state.channelKeyPending, channelId),
        channelRecoveryPending: withoutChannel(state.channelRecoveryPending, channelId),
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
    keyReconciliationPromises.clear();
    channelEpochs.clear();
    residentChannelOrder.clear();
    messageDecryptWorkers.reset();
    set({
      eventsByChannel: {},
      messagesByChannel: {},
      isLoading: false,
      loadingByChannel: {},
      loadingMoreByChannel: {},
      hasMore: {},
      cursors: {},
      securityErrors: {},
      channelKeyPending: {},
      channelRecoveryPending: {},
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
