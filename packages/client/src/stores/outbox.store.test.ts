import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { OutboxCommand } from './outbox-model';
import { createOutboxCommand, outboxItemFromCommand } from './outbox-model';

type TestContext = Readonly<{ userId: string; deviceId: string }>;

const localState = vi.hoisted(() => {
  const accountA: TestContext = Object.freeze({
    userId: '11111111-1111-4111-8111-111111111111',
    deviceId: '22222222-2222-4222-8222-222222222222',
  });
  const accountB: TestContext = Object.freeze({
    userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    deviceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  });
  const active = { value: accountA };
  return {
    accountA,
    accountB,
    active,
    captureContext: vi.fn(() => active.value),
    isContextCurrent: vi.fn((context: TestContext) => (
      context.userId === active.value.userId && context.deviceId === active.value.deviceId
    )),
    saveCommand: vi.fn(),
    loadCommands: vi.fn(),
    loadCommand: vi.fn(),
    deleteCommand: vi.fn(),
    deleteChannel: vi.fn(),
  };
});

const messageState = vi.hoisted(() => ({
  sendMessage: vi.fn(),
}));

vi.mock('../services/local-state.service', () => ({
  captureOutboxStorageContext: localState.captureContext,
  isOutboxStorageContextCurrent: localState.isContextCurrent,
  saveOutboxCommand: localState.saveCommand,
  loadOutboxCommands: localState.loadCommands,
  loadOutboxCommand: localState.loadCommand,
  deleteOutboxCommand: localState.deleteCommand,
  deleteOutboxCommandsForChannel: localState.deleteChannel,
}));

vi.mock('./message.store', () => ({
  useMessageStore: {
    getState: () => ({ sendMessage: messageState.sendMessage }),
  },
}));

import { useOutboxStore } from './outbox.store';

const channelId = '33333333-3333-4333-8333-333333333333';

beforeEach(() => {
  vi.stubGlobal('navigator', { onLine: true });
  useOutboxStore.getState().reset();
  localState.active.value = localState.accountA;
  localState.captureContext.mockClear();
  localState.isContextCurrent.mockClear();
  localState.saveCommand.mockReset().mockImplementation(async () => undefined);
  localState.loadCommands.mockReset().mockImplementation(async () => []);
  localState.loadCommand.mockReset().mockImplementation(async () => null);
  localState.deleteCommand.mockReset().mockImplementation(async () => undefined);
  localState.deleteChannel.mockReset().mockImplementation(async () => undefined);
  messageState.sendMessage.mockReset().mockImplementation(async () => undefined);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('outbox principal and persistence lifecycle', () => {
  it('rejects a new command before persistence when the bounded outbox is full', async () => {
    const { MAX_OUTBOX_COMMANDS_PER_DEVICE } = await import('./outbox-model');
    const items = Object.fromEntries(Array.from({ length: MAX_OUTBOX_COMMANDS_PER_DEVICE }, (_, index) => {
      const command = createOutboxCommand(
        { channelId, content: `queued-${index}` },
        () => `${String(index).padStart(8, '0')}-0000-4000-8000-000000000000`,
        () => `2026-01-01T00:00:${String(index % 60).padStart(2, '0')}.000Z`,
      );
      return [command.idempotencyKey, outboxItemFromCommand(command)];
    }));
    useOutboxStore.setState({ items, isInitialized: true });

    await expect(useOutboxStore.getState().enqueue(channelId, 'one too many')).rejects.toThrow('OUTBOX_CAPACITY');
    expect(localState.saveCommand).not.toHaveBeenCalled();
  });

  it('orders channel cleanup after a save already in flight', async () => {
    const save = promiseWithResolvers<void>();
    const order: string[] = [];
    localState.saveCommand.mockImplementation(async () => {
      order.push('save-start');
      await save.promise;
      order.push('save-finished');
    });
    localState.deleteChannel.mockImplementation(async () => {
      order.push('channel-deleted');
    });

    const enqueue = useOutboxStore.getState().enqueue(channelId, 'secret queued before revocation');
    await vi.waitFor(() => expect(localState.saveCommand).toHaveBeenCalledTimes(1));

    const cleanup = useOutboxStore.getState().clearChannel(channelId);
    await Promise.resolve();
    expect(localState.deleteChannel).not.toHaveBeenCalled();

    save.resolve();
    await Promise.all([enqueue, cleanup]);

    expect(order).toEqual(['save-start', 'save-finished', 'channel-deleted']);
    expect(localState.saveCommand.mock.calls[0]?.[0]).toBe(localState.accountA);
    expect(localState.saveCommand.mock.calls[0]?.[2]()).toBe(false);
    expect(localState.deleteChannel).toHaveBeenCalledWith(localState.accountA, channelId);
    expect(useOutboxStore.getState().items).toEqual({});
  });

  it('does not send plaintext loaded before reset under a different principal', async () => {
    const command = fixedCommand('stale plaintext');
    const load = promiseWithResolvers<OutboxCommand | null>();
    localState.loadCommand.mockReturnValue(load.promise);
    useOutboxStore.setState({
      items: { [command.idempotencyKey]: outboxItemFromCommand(command) },
      isInitialized: true,
    });

    const flushing = useOutboxStore.getState().flushItem(command.idempotencyKey);
    await vi.waitFor(() => expect(localState.loadCommand).toHaveBeenCalledTimes(1));
    expect(localState.loadCommand).toHaveBeenCalledWith(localState.accountA, command.idempotencyKey);

    useOutboxStore.getState().reset();
    localState.active.value = localState.accountB;
    load.resolve(command);
    await flushing;

    expect(messageState.sendMessage).not.toHaveBeenCalled();
    expect(localState.deleteCommand).not.toHaveBeenCalled();
    expect(useOutboxStore.getState().items).toEqual({});
  });

  it('preserves a legitimate enqueue, send, and exact-context delete', async () => {
    let persisted: OutboxCommand | null = null;
    localState.saveCommand.mockImplementation(async (_context, command: OutboxCommand) => {
      persisted = command;
    });
    localState.loadCommand.mockImplementation(async () => persisted);

    const idempotencyKey = await useOutboxStore.getState().enqueue(channelId, 'ordinary message');
    await vi.waitFor(() => expect(localState.deleteCommand).toHaveBeenCalledTimes(1));

    expect(Object.isFrozen(localState.saveCommand.mock.calls[0]?.[0])).toBe(true);
    expect(localState.saveCommand).toHaveBeenCalledWith(
      localState.accountA,
      expect.objectContaining({
        channelId,
        content: 'ordinary message',
        idempotencyKey,
      }),
      expect.any(Function),
    );
    expect(localState.loadCommand).toHaveBeenCalledWith(localState.accountA, idempotencyKey);
    expect(messageState.sendMessage).toHaveBeenCalledWith(
      channelId,
      'ordinary message',
      undefined,
      idempotencyKey,
    );
    expect(localState.deleteCommand).toHaveBeenCalledWith(localState.accountA, idempotencyKey);
    expect(useOutboxStore.getState().items[idempotencyKey]).toBeUndefined();
  });
});

function fixedCommand(content: string): OutboxCommand {
  return createOutboxCommand(
    { channelId, content },
    () => '44444444-4444-4444-8444-444444444444',
    () => '2026-01-01T00:00:00.000Z',
  );
}

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
