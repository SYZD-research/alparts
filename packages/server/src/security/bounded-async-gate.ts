interface GateWaiter {
  resolve: () => void;
  reject: (error: Error) => void;
  timer?: NodeJS.Timeout;
}

export interface BoundedAsyncGateOptions {
  busyError: string;
  timeoutError: string;
}

/**
 * A small in-process bulkhead with a bounded FIFO wait queue.
 *
 * The gate is deliberately generic so CPU-heavy work and remote I/O use the
 * same admission semantics. Multi-process deployments still need an external
 * admission layer; this class bounds one process and exposes only aggregate
 * counters suitable for low-cardinality metrics.
 */
export class BoundedAsyncGate {
  private active = 0;
  private readonly waiters: GateWaiter[] = [];

  constructor(
    private readonly concurrency: number,
    private readonly maxPending: number,
    private readonly errors: BoundedAsyncGateOptions,
  ) {
    if (
      !Number.isSafeInteger(concurrency)
      || concurrency < 1
      || !Number.isSafeInteger(maxPending)
      || maxPending < 0
      || !errors.busyError
      || !errors.timeoutError
    ) {
      throw new Error('INVALID_ASYNC_GATE_LIMIT');
    }
  }

  async run<T>(operation: () => Promise<T>, deadline?: number): Promise<T> {
    const release = await this.acquireLease(deadline);
    try {
      return await operation();
    } finally {
      release();
    }
  }

  async acquireLease(deadline?: number): Promise<() => void> {
    await this.acquire(deadline);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.release();
    };
  }

  snapshot(): Readonly<{ active: number; pending: number; concurrency: number; maxPending: number }> {
    return {
      active: this.active,
      pending: this.waiters.length,
      concurrency: this.concurrency,
      maxPending: this.maxPending,
    };
  }

  private acquire(deadline?: number): Promise<void> {
    if (deadline !== undefined && deadline <= Date.now()) {
      return Promise.reject(new Error(this.errors.timeoutError));
    }
    if (this.active < this.concurrency) {
      this.active += 1;
      return Promise.resolve();
    }
    if (this.waiters.length >= this.maxPending) {
      return Promise.reject(new Error(this.errors.busyError));
    }
    return new Promise((resolve, reject) => {
      const waiter: GateWaiter = { resolve, reject };
      if (deadline !== undefined) {
        waiter.timer = setTimeout(() => {
          const index = this.waiters.indexOf(waiter);
          if (index < 0) return;
          this.waiters.splice(index, 1);
          reject(new Error(this.errors.timeoutError));
        }, Math.max(0, deadline - Date.now()));
        waiter.timer.unref();
      }
      this.waiters.push(waiter);
    });
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      if (next.timer) clearTimeout(next.timer);
      next.resolve();
      return;
    }
    this.active -= 1;
  }
}
