import { create } from 'zustand';
import { MAX_MESSAGE_LENGTH } from '@alparts/shared';
import {
  captureOutboxStorageContext,
  deleteOutboxCommand,
  deleteOutboxCommandsForChannel,
  isOutboxStorageContextCurrent,
  loadOutboxCommand,
  loadOutboxCommands,
  saveOutboxCommand,
  type OutboxStorageContext,
} from '../services/local-state.service';
import { useMessageStore } from './message.store';
import {
  createOutboxCommand,
  outboxItemFromCommand,
  transitionOutboxItem,
  type OutboxItem,
} from './outbox-model';

export type { OutboxItem, OutboxStatus } from './outbox-model';

interface OutboxState {
  items: Record<string, OutboxItem>;
  isInitialized: boolean;
  isFlushing: boolean;
  errorsByChannel: Record<string, string | null>;
  initialize: () => Promise<void>;
  enqueue: (channelId: string, content: string, refMessageId?: string) => Promise<string>;
  flushAll: () => Promise<void>;
  flushItem: (idempotencyKey: string) => Promise<void>;
  retry: (idempotencyKey: string) => void;
  clearError: (channelId: string) => void;
  clearChannel: (channelId: string) => Promise<void>;
  reset: () => void;
}

const sending = new Set<string>();
const persistenceQueues = new Map<string, Promise<void>>();
let outboxGeneration = 0;
let initialization: Promise<void> | null = null;

interface OutboxLifecycle {
  generation: number;
  context: OutboxStorageContext;
}

function captureOutboxLifecycle(): OutboxLifecycle {
  return {
    generation: outboxGeneration,
    context: captureOutboxStorageContext(),
  };
}

function isOutboxLifecycleCurrent(lifecycle: OutboxLifecycle): boolean {
  return lifecycle.generation === outboxGeneration
    && isOutboxStorageContextCurrent(lifecycle.context);
}

function persistenceScope(context: OutboxStorageContext, channelId: string): string {
  return JSON.stringify([context.userId, context.deviceId, channelId]);
}

function sendingScope(context: OutboxStorageContext, idempotencyKey: string): string {
  return JSON.stringify([context.userId, context.deviceId, idempotencyKey]);
}

function queuePersistence(
  context: OutboxStorageContext,
  channelId: string,
  operation: () => Promise<void>,
): Promise<void> {
  const scope = persistenceScope(context, channelId);
  const previous = persistenceQueues.get(scope) || Promise.resolve();
  const next = previous.catch(() => undefined).then(operation);
  persistenceQueues.set(scope, next);
  void next.catch(() => undefined).finally(() => {
    if (persistenceQueues.get(scope) === next) persistenceQueues.delete(scope);
  });
  return next;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function isOnline(): boolean {
  return typeof navigator === 'undefined' || navigator.onLine;
}

function validateContent(content: string): void {
  if (
    !content
    || content.length > MAX_MESSAGE_LENGTH
    || new TextEncoder().encode(content).length > MAX_MESSAGE_LENGTH * 4
  ) throw new Error('メッセージが長すぎます');
}

export const useOutboxStore = create<OutboxState>((set, get) => ({
  items: {},
  isInitialized: false,
  isFlushing: false,
  errorsByChannel: {},

  initialize: async () => {
    if (get().isInitialized) return;
    if (initialization) return initialization;
    const lifecycle = captureOutboxLifecycle();
    initialization = (async () => {
      try {
        const commands = await loadOutboxCommands(lifecycle.context);
        if (!isOutboxLifecycleCurrent(lifecycle)) return;
        const restored = Object.fromEntries(commands.map((command) => [
          command.idempotencyKey,
          outboxItemFromCommand(command),
        ]));
        set((state) => ({ items: { ...restored, ...state.items }, isInitialized: true }));
      } finally {
        if (lifecycle.generation === outboxGeneration) initialization = null;
      }
    })();
    return initialization;
  },

  enqueue: async (channelId, content, refMessageId) => {
    const lifecycle = captureOutboxLifecycle();
    try {
      validateContent(content);
      const command = createOutboxCommand({ channelId, content, refMessageId });
      await queuePersistence(
        lifecycle.context,
        channelId,
        () => saveOutboxCommand(
          lifecycle.context,
          command,
          () => isOutboxLifecycleCurrent(lifecycle),
        ),
      );
      if (!isOutboxLifecycleCurrent(lifecycle)) return command.idempotencyKey;
      set((state) => ({
        items: {
          ...state.items,
          [command.idempotencyKey]: outboxItemFromCommand(command),
        },
        errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
      }));
      if (isOnline()) void get().flushItem(command.idempotencyKey);
      return command.idempotencyKey;
    } catch (error) {
      if (isOutboxLifecycleCurrent(lifecycle)) {
        set((state) => ({
          errorsByChannel: {
            ...state.errorsByChannel,
            [channelId]: errorMessage(error, 'メッセージを暗号化outboxへ保存できませんでした'),
          },
        }));
      }
      throw error;
    }
  },

  flushItem: async (idempotencyKey) => {
    if (!isOnline()) return;
    const item = get().items[idempotencyKey];
    if (!item) return;
    const lifecycle = captureOutboxLifecycle();
    const scopedSendingId = sendingScope(lifecycle.context, idempotencyKey);
    if (sending.has(scopedSendingId)) return;
    sending.add(scopedSendingId);
    set((state) => ({
      items: {
        ...state.items,
        [idempotencyKey]: transitionOutboxItem(state.items[idempotencyKey], { type: 'send' }),
      },
    }));
    try {
      const command = await loadOutboxCommand(lifecycle.context, idempotencyKey);
      if (!isOutboxLifecycleCurrent(lifecycle)) return;
      if (!command) {
        set((state) => {
          const items = { ...state.items };
          delete items[idempotencyKey];
          return { items };
        });
        return;
      }
      if (!isOutboxLifecycleCurrent(lifecycle)) return;
      await useMessageStore.getState().sendMessage(
        command.channelId,
        command.content,
        command.refMessageId,
        command.idempotencyKey,
      );
      if (!isOutboxLifecycleCurrent(lifecycle)) return;
      await queuePersistence(lifecycle.context, command.channelId, async () => {
        if (!isOutboxLifecycleCurrent(lifecycle)) return;
        await deleteOutboxCommand(lifecycle.context, command.idempotencyKey);
      });
      if (!isOutboxLifecycleCurrent(lifecycle)) return;
      set((state) => {
        const items = { ...state.items };
        delete items[idempotencyKey];
        return { items };
      });
    } catch (error) {
      if (isOutboxLifecycleCurrent(lifecycle)) {
        set((state) => ({
          items: {
            ...state.items,
            [idempotencyKey]: transitionOutboxItem(state.items[idempotencyKey], {
              type: 'fail',
              error: errorMessage(error, '送信に失敗しました'),
            }),
          },
        }));
      }
    } finally {
      sending.delete(scopedSendingId);
    }
  },

  flushAll: async () => {
    if (!isOnline()) return;
    const lifecycle = captureOutboxLifecycle();
    try {
      await get().initialize();
      if (!isOutboxLifecycleCurrent(lifecycle)) return;
    } catch {
      return;
    }
    if (get().isFlushing) return;
    const generation = outboxGeneration;
    set({ isFlushing: true });
    try {
      const ids = Object.values(get().items)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id))
        .map((item) => item.id);
      for (const id of ids) {
        if (generation !== outboxGeneration || !isOutboxLifecycleCurrent(lifecycle) || !isOnline()) break;
        await get().flushItem(id);
        if (!isOutboxLifecycleCurrent(lifecycle)) break;
      }
    } finally {
      if (generation === outboxGeneration && isOutboxStorageContextCurrent(lifecycle.context)) {
        set({ isFlushing: false });
      }
    }
  },

  retry: (idempotencyKey) => {
    const item = get().items[idempotencyKey];
    if (!item) return;
    if (!isOnline()) {
      set((state) => ({
        items: {
          ...state.items,
          [idempotencyKey]: transitionOutboxItem(item, {
            type: 'queue',
            error: 'オフラインです。接続復旧後に再送します',
          }),
        },
      }));
      return;
    }
    void get().flushItem(idempotencyKey);
  },

  clearError: (channelId) => set((state) => ({
    errorsByChannel: { ...state.errorsByChannel, [channelId]: null },
  })),

  clearChannel: async (channelId) => {
    let context: OutboxStorageContext | null = null;
    try {
      context = captureOutboxStorageContext();
    } catch {
      // Memory cleanup must still complete if authentication disappeared first.
    }
    // Invalidate response handlers before removing plaintext. Other channel
    // items stay visible and return to queued so an unrelated in-flight send
    // can be reconciled idempotently on the next flush.
    outboxGeneration += 1;
    initialization = null;
    sending.clear();
    set((state) => {
      const items = Object.fromEntries(Object.entries(state.items)
        .filter(([, item]) => item.channelId !== channelId)
        .map(([id, item]) => [id, item.status === 'sending'
          ? transitionOutboxItem(item, { type: 'queue' })
          : item]));
      const errorsByChannel = { ...state.errorsByChannel };
      delete errorsByChannel[channelId];
      return { items, errorsByChannel, isFlushing: false };
    });
    if (context) {
      await queuePersistence(
        context,
        channelId,
        () => deleteOutboxCommandsForChannel(context, channelId),
      ).catch(() => undefined);
    }
  },

  reset: () => {
    outboxGeneration += 1;
    initialization = null;
    sending.clear();
    set({ items: {}, isInitialized: false, isFlushing: false, errorsByChannel: {} });
  },
}));
