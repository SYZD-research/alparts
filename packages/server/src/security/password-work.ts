import { AsyncLocalStorage } from 'node:async_hooks';
import { matchesPasswordHash, passwordSalt, protectPasswordHash } from './password-pepper.js';
import { createRequire } from 'node:module';
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

const bcryptModulePath = createRequire(import.meta.url).resolve('bcryptjs');
const workerSource = String.raw`
  'use strict';
  const { parentPort, workerData } = require('node:worker_threads');
  const bcrypt = require(workerData.bcryptModulePath);
  parentPort.on('message', (task) => {
    try {
      if (!task || !Number.isSafeInteger(task.id) || typeof task.password !== 'string') {
        throw new Error('INVALID_PASSWORD_TASK');
      }
      const passwordBytes = Buffer.byteLength(task.password, 'utf8');
      if (passwordBytes < 1 || passwordBytes > 72) throw new Error('INVALID_PASSWORD_TASK');
      let value;
      if (task.kind === 'hash') {
        if (!Number.isSafeInteger(task.rounds) || task.rounds < 12 || task.rounds > 15) {
          throw new Error('INVALID_PASSWORD_TASK');
        }
        value = bcrypt.hashSync(task.password, task.rounds);
      } else if (task.kind === 'derive') {
        if (typeof task.salt !== 'string' || !/^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{22}$/.test(task.salt)) {
          throw new Error('INVALID_PASSWORD_TASK');
        }
        value = bcrypt.hashSync(task.password, task.salt);
      } else {
        throw new Error('INVALID_PASSWORD_TASK');
      }
      parentPort.postMessage({ id: task.id, ok: true, value });
    } catch {
      parentPort.postMessage({ id: task && task.id, ok: false });
    }
  });
`;

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

export function verifyPassword(password: string, hash: string): Promise<boolean> {
  return runPasswordWork(async () => matchesPasswordHash(hash, String(await submitPasswordTask({ kind: 'derive', password, salt: passwordSalt(hash) }))));
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
  const worker = new Worker(workerSource, {
    eval: true,
    name: 'alparts-password-worker',
    workerData: { bcryptModulePath },
  });
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
