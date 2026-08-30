import { describe, expect, it } from 'vitest';
import { CoalescedChannelWorker } from './coalesced-channel-worker';

describe('bounded coalesced channel worker', () => {
  it('runs one active pass plus one coalesced pass for a burst', async () => {
    const worker = new CoalescedChannelWorker(2);
    const firstPass = promiseWithResolvers<void>();
    let passes = 0;
    const operation = async () => {
      passes += 1;
      if (passes === 1) await firstPass.promise;
    };

    const first = worker.run('channel-a', operation);
    await Promise.resolve();
    const second = worker.run('channel-a', operation);
    const third = worker.run('channel-a', operation);
    expect(second).toBe(first);
    expect(third).toBe(first);
    expect(worker.activeScopes()).toBe(1);

    firstPass.resolve();
    await first;
    expect(passes).toBe(2);
    expect(worker.activeScopes()).toBe(0);
  });

  it('rejects a new scope at capacity and cancellation prevents a pending pass', async () => {
    const worker = new CoalescedChannelWorker(1);
    const gate = promiseWithResolvers<void>();
    let passes = 0;
    const observed: { signal?: AbortSignal } = {};
    const running = worker.run('channel-a', async (signal) => {
      observed.signal = signal;
      passes += 1;
      await gate.promise;
    });
    await Promise.resolve();
    await expect(worker.run('channel-b', async () => undefined)).rejects.toThrow('COALESCED_WORK_CAPACITY');
    void worker.run('channel-a', async () => { passes += 1; });
    worker.cancel('channel-a');
    expect(observed.signal).toBeDefined();
    expect(observed.signal?.aborted).toBe(true);
    expect(worker.activeScopes()).toBe(1);
    await expect(worker.run('channel-b', async () => undefined)).rejects.toThrow('COALESCED_WORK_CAPACITY');
    gate.resolve();
    await running;
    expect(passes).toBe(1);
    expect(worker.activeScopes()).toBe(0);
  });

  it('aborts a scope that exceeds its bounded execution lifetime', async () => {
    const worker = new CoalescedChannelWorker(1, 10);
    const running = worker.run('channel-a', (signal) => new Promise<void>((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }));
    await expect(running).rejects.toThrow('COALESCED_WORK_TIMEOUT');
    expect(worker.activeScopes()).toBe(0);
  });
});

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
