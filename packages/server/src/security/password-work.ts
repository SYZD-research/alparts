import { AsyncLocalStorage } from 'node:async_hooks';
import { comparePasswordHash, passwordSalt, protectPasswordHash, type PasswordHashMatch } from './password-pepper.js';
import { Worker } from 'node:worker_threads';
import { BoundedAsyncGate } from './bounded-async-gate.js';
import {
  MAX_CONCURRENT_PASSWORD_WORK,
  MAX_PENDING_PASSWORD_WORK,
  PASSWORD_WORK_EXECUTION_MS,
  PASSWORD_WORK_WAIT_MS,
} from './limits.js';

const passwordWorkGate = new BoundedAsyncGate(
  MAX_CONCURRENT_PASSWORD_WORK,
  MAX_PENDING_PASSWORD_WORK,
  { busyError: 'AUTH_CAPACITY', timeoutError: 'AUTH_CAPACITY' },
);

type PasswordTask =
  | { kind: 'hash'; password: string; rounds: number }
  | { kind: 'derive'; password: string; salt: string };

interface WorkerReply {
  id: number;
  ok: boolean;
  value?: string | boolean;
}

interface ActiveWorkerTask {
  id: number;
  resolve: (value: string | boolean) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
}

interface PasswordWorkerSlot {
  worker: Worker;
  active: ActiveWorkerTask | null;
  failed: boolean;
  publicWork: boolean;
}

// Source runs under tsx; the compiled build ships the sibling .js file.
const workerUrl = new URL(
  import.meta.url.endsWith('.ts') ? './password-worker.ts' : './password-worker.js',
  import.meta.url,
);

// Public work holds admission until its audit commit finishes. Consequently at
// most two unauthenticated requests can occupy the global audit queue.
const publicAuthenticationGate = new BoundedAsyncGate(2, 0, { busyError: 'AUTH_CAPACITY', timeoutError: 'AUTH_CAPACITY' });
const publicContext = new AsyncLocalStorage<boolean>();
export function runPublicAuthentication<T>(operation: () => Promise<T>): Promise<T> {
  return publicAuthenticationGate.run(() => publicContext.run(true, operation));
}
export function publicAuthenticationSnapshot() { return publicAuthenticationGate.snapshot(); }

const workerSlots: PasswordWorkerSlot[] = [];
let nextTaskId = 1;
let workersClosing = false;

/** Generic admission hook retained for deterministic bulkhead tests. */
export function runPasswordWork<T>(operation: () => Promise<T>): Promise<T> {
  return publicContext.getStore() ? operation() : passwordWorkGate.run(operation, Date.now() + PASSWORD_WORK_WAIT_MS);
}

export function hashPassword(password: string, rounds: number): Promise<string> {
  return runPasswordWork(async () => protectPasswordHash(String(await submitPasswordTask({ kind: 'hash', password, rounds }))));
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return (await verifyPasswordForUpgrade(password, hash)).valid;
}

/** Like verifyPassword, but also returns the rewrapped hash after a pepper rotation. */
export function verifyPasswordForUpgrade(password: string, hash: string): Promise<PasswordHashMatch> {
  return runPasswordWork(async () => comparePasswordHash(hash, String(await submitPasswordTask({ kind: 'derive', password, salt: passwordSalt(hash) }))));
}

export function passwordWorkSnapshot() {
  return passwordWorkGate.snapshot();
}

export function passwordWorkerSnapshot() {
  return {
    workers: workerSlots.length,
    busy: workerSlots.filter((slot) => slot.active !== null).length,
    threadIds: workerSlots.map((slot) => slot.worker.threadId).filter((id) => id > 0),
  };
}

export async function closePasswordWorkers(): Promise<void> {
  workersClosing = true;
  const slots = workerSlots.splice(0);
  for (const slot of slots) {
    if (slot.active) {
      clearTimeout(slot.active.timeout);
      slot.active.reject(new Error('AUTH_SHUTDOWN'));
      slot.active = null;
    }
  }
  await Promise.allSettled(slots.map((slot) => slot.worker.terminate()));
}

function submitPasswordTask(task: PasswordTask): Promise<string | boolean> {
  if (workersClosing) return Promise.reject(new Error('AUTH_SHUTDOWN'));
  const publicWork = publicContext.getStore() === true;
  let slot = workerSlots.find((candidate) => candidate.publicWork === publicWork && !candidate.failed && candidate.active === null);
  if (!slot && workerSlots.filter((candidate) => candidate.publicWork === publicWork).length < MAX_CONCURRENT_PASSWORD_WORK) {
    slot = createPasswordWorker(publicWork);
    workerSlots.push(slot);
  }
  if (!slot) return Promise.reject(new Error('AUTH_CAPACITY'));
  const id = nextTaskId;
  nextTaskId = nextTaskId === Number.MAX_SAFE_INTEGER ? 1 : nextTaskId + 1;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      failWorker(slot!, new Error('PASSWORD_WORK_TIMEOUT'));
    }, PASSWORD_WORK_EXECUTION_MS);
    timeout.unref();
    slot!.active = { id, resolve, reject, timeout };
    try {
      slot!.worker.postMessage({ id, ...task });
    } catch {
      failWorker(slot!, new Error('PASSWORD_WORKER_FAILED'));
    }
  });
}

function createPasswordWorker(publicWork: boolean): PasswordWorkerSlot {
  const worker = new Worker(workerUrl, { name: 'alparts-password-worker' });
  const slot: PasswordWorkerSlot = { worker, active: null, failed: false, publicWork };
  worker.on('message', (reply: WorkerReply) => {
    const active = slot.active;
    if (!active || reply.id !== active.id) {
      failWorker(slot, new Error('PASSWORD_WORKER_PROTOCOL_ERROR'));
      return;
    }
    clearTimeout(active.timeout);
    slot.active = null;
    if (reply.ok && (typeof reply.value === 'string' || typeof reply.value === 'boolean')) {
      active.resolve(reply.value);
    } else {
      active.reject(new Error('PASSWORD_WORK_FAILED'));
    }
  });
  worker.on('error', () => failWorker(slot, new Error('PASSWORD_WORKER_FAILED')));
  worker.on('exit', (code) => {
    if (code !== 0 && !slot.failed && !workersClosing) {
      failWorker(slot, new Error('PASSWORD_WORKER_FAILED'));
    } else {
      removeWorker(slot);
    }
  });
  // The HTTP request and its promise own task lifetime; idle workers must not
  // keep a drained process alive during shutdown or one-shot CLI execution.
  worker.unref();
  return slot;
}

function failWorker(slot: PasswordWorkerSlot, error: Error): void {
  if (slot.failed) return;
  slot.failed = true;
  const active = slot.active;
  slot.active = null;
  if (active) {
    clearTimeout(active.timeout);
    active.reject(error);
  }
  removeWorker(slot);
  void slot.worker.terminate();
}

function removeWorker(slot: PasswordWorkerSlot): void {
  const index = workerSlots.indexOf(slot);
  if (index >= 0) workerSlots.splice(index, 1);
}
