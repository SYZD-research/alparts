interface WorkerState {
  pending: boolean;
  cancelled: boolean;
  controller: AbortController;
  timeout: ReturnType<typeof setTimeout>;
  promise: Promise<void>;
}

export const DEFAULT_COALESCED_WORK_TIMEOUT_MS = 30_000;

/**
 * Runs at most one operation per scope and represents every burst by one
 * additional pass. The pending state is a boolean, never an attacker-sized
 * queue. Capacity overflow fails promptly so a caller can reconcile via REST.
 */
export class CoalescedChannelWorker {
  private readonly workers = new Map<string, WorkerState>();

  constructor(
    private readonly maximumScopes: number,
    private readonly maximumOperationMs = DEFAULT_COALESCED_WORK_TIMEOUT_MS,
  ) {
    if (!Number.isSafeInteger(maximumScopes) || maximumScopes < 1) {
      throw new Error('Invalid coalesced worker capacity');
    }
    if (!Number.isSafeInteger(maximumOperationMs) || maximumOperationMs < 1 || maximumOperationMs > 300_000) {
      throw new Error('Invalid coalesced worker timeout');
    }
  }

  run(scopeId: string, operation: (signal: AbortSignal) => Promise<void>): Promise<void> {
    const existing = this.workers.get(scopeId);
    if (existing) {
      if (!existing.cancelled) existing.pending = true;
      return existing.promise;
    }
    if (this.workers.size >= this.maximumScopes) {
      return Promise.reject(new Error('COALESCED_WORK_CAPACITY'));
    }

    const controller = new AbortController();
    const state = {} as WorkerState;
    Object.assign(state, {
      pending: true,
      cancelled: false,
      controller,
      timeout: setTimeout(() => {
        state.cancelled = true;
        state.pending = false;
        controller.abort(new Error('COALESCED_WORK_TIMEOUT'));
      }, this.maximumOperationMs),
      promise: Promise.resolve(),
    });
    this.workers.set(scopeId, state);
    state.promise = Promise.resolve().then(async () => {
      while (!state.cancelled && state.pending) {
        state.pending = false;
        await operation(controller.signal);
      }
    }).finally(() => {
      clearTimeout(state.timeout);
      if (this.workers.get(scopeId) === state) this.workers.delete(scopeId);
    });
    return state.promise;
  }

  cancel(scopeId: string): void {
    const state = this.workers.get(scopeId);
    if (!state) return;
    state.cancelled = true;
    state.pending = false;
    state.controller.abort(new Error('COALESCED_WORK_CANCELLED'));
  }

  reset(): void {
    for (const scopeId of this.workers.keys()) this.cancel(scopeId);
  }

  activeScopes(): number {
    return this.workers.size;
  }
}
