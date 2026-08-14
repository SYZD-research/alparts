import { create } from 'zustand';
import { api } from '../services/api';
import { encryptMessage, decryptMessage, generateChannelKey } from '../services/crypto.service';
import type { Message } from '@alparts/shared';

interface MessageState {
  messagesByChannel: Record<string, Message[]>;
  channelKeys: Record<string, string>; // channelId -> channel key JWK
  isLoading: boolean;
  hasMore: Record<string, boolean>;
  cursors: Record<string, string | null>;

  loadMessages: (channelId: string, append?: boolean) => Promise<void>;
  loadMoreMessages: (channelId: string) => Promise<void>;
  sendMessage: (channelId: string, content: string, refMessageId?: string) => Promise<void>;
  addMessage: (channelId: string, message: Message) => void;
  editMessage: (messageId: string, channelId: string, content: string) => Promise<void>;
  deleteMessage: (messageId: string, channelId: string) => Promise<void>;
  toggleReaction: (messageId: string, emoji: string) => Promise<void>;
  setChannelKey: (channelId: string, key: string) => void;
  decryptMessages: (channelId: string) => Promise<void>;
}

export const useMessageStore = create<MessageState>((set, get) => ({
  messagesByChannel: {},
  channelKeys: {},
  isLoading: false,
  hasMore: {},
  cursors: {},

  loadMessages: async (channelId) => {
    set({ isLoading: true });
    try {
      const result = await api.getMessages(channelId);
      set(state => ({
        messagesByChannel: {
          ...state.messagesByChannel,
          [channelId]: result.data,
        },
        hasMore: { ...state.hasMore, [channelId]: result.hasMore },
        cursors: { ...state.cursors, [channelId]: result.cursor },
        isLoading: false,
      }));
      // Try to decrypt
      await get().decryptMessages(channelId);
    } catch {
      set({ isLoading: false });
    }
  },

  loadMoreMessages: async (channelId) => {
    const cursor = get().cursors[channelId];
    if (!cursor || !get().hasMore[channelId]) return;

    try {
      const result = await api.getMessages(channelId, cursor);
      set(state => ({
        messagesByChannel: {
          ...state.messagesByChannel,
          [channelId]: [...(state.messagesByChannel[channelId] || []), ...result.data],
        },
        hasMore: { ...state.hasMore, [channelId]: result.hasMore },
        cursors: { ...state.cursors, [channelId]: result.cursor },
      }));
      await get().decryptMessages(channelId);
    } catch {
      // ignore
    }
  },

  sendMessage: async (channelId, content, refMessageId) => {
    const channelKey = get().channelKeys[channelId];
    const idempotencyKey = crypto.randomUUID();

    let encryptedContent = content;
    let contentNonce = '';

    if (channelKey) {
      const encrypted = await encryptMessage(content, channelKey);
      encryptedContent = encrypted.encrypted;
      contentNonce = encrypted.nonce;
    }

    try {
      const message = await api.sendMessage(channelId, {
        encryptedContent,
        contentNonce,
        idempotencyKey,
        refMessageId,
      });

      // Decrypt locally for display
      if (channelKey) {
        message.content = content;
      }

      set(state => ({
        messagesByChannel: {
          ...state.messagesByChannel,
          [channelId]: [...(state.messagesByChannel[channelId] || []), message],
        },
      }));
    } catch (err) {
      throw err;
    }
  },

  addMessage: (channelId, message) => {
    set(state => {
      const existing = state.messagesByChannel[channelId] || [];
      // Avoid duplicates
      if (existing.some(m => m.id === message.id)) return state;
      return {
        messagesByChannel: {
          ...state.messagesByChannel,
          [channelId]: [...existing, message],
        },
      };
    });
    // Decrypt new message
    get().decryptMessages(channelId);
  },

  editMessage: async (messageId, channelId, content) => {
    const channelKey = get().channelKeys[channelId];
    let encryptedContent = content;
    let contentNonce = '';

    if (channelKey) {
      const encrypted = await encryptMessage(content, channelKey);
      encryptedContent = encrypted.encrypted;
      contentNonce = encrypted.nonce;
    }

    await api.editMessage(messageId, { encryptedContent, contentNonce });
  },

  deleteMessage: async (messageId, channelId) => {
    await api.deleteMessage(messageId);
    set(state => ({
      messagesByChannel: {
        ...state.messagesByChannel,
        [channelId]: (state.messagesByChannel[channelId] || []).filter(m => m.id !== messageId),
      },
    }));
  },

  toggleReaction: async (messageId, emoji) => {
    await api.toggleReaction(messageId, emoji);
  },

  setChannelKey: (channelId, key) => {
    set(state => ({
      channelKeys: { ...state.channelKeys, [channelId]: key },
    }));
  },

  decryptMessages: async (channelId) => {
    const channelKey = get().channelKeys[channelId];
    if (!channelKey) return;

    const messages = get().messagesByChannel[channelId] || [];
    const decrypted = await Promise.all(
      messages.map(async (msg) => {
        try {
          if (msg.encryptedContent && msg.contentNonce) {
            const plaintext = await decryptMessage(msg.encryptedContent, msg.contentNonce, channelKey);
            return { ...msg, content: plaintext };
          }
          return msg;
        } catch {
          return msg;
        }
      }),
    );

    set(state => ({
      messagesByChannel: {
        ...state.messagesByChannel,
        [channelId]: decrypted,
      },
    }));
  },
}));
