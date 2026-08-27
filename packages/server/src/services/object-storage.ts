import * as http from 'node:http';
import * as https from 'node:https';
import * as Minio from 'minio';
import { config } from '../config/index.js';
import type { Readable } from 'node:stream';

export const MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS = 8;
export const MAX_PENDING_OBJECT_STORAGE_OPERATIONS = 32;

interface GateWaiter {
  resolve: () => void;
  reject: (error: Error) => void;
  timer?: NodeJS.Timeout;
}

export class BoundedAsyncGate {
  private active = 0;
  private readonly waiters: GateWaiter[] = [];

  constructor(
    private readonly concurrency: number,
    private readonly maxPending: number,
  ) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || !Number.isSafeInteger(maxPending) || maxPending < 0) {
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

  private acquire(deadline?: number): Promise<void> {
    if (deadline !== undefined && deadline <= Date.now()) {
      return Promise.reject(new Error('OBJECT_STORAGE_TIMEOUT'));
    }
    if (this.active < this.concurrency) {
      this.active += 1;
      return Promise.resolve();
    }
    if (this.waiters.length >= this.maxPending) return Promise.reject(new Error('OBJECT_STORAGE_BUSY'));
    return new Promise((resolve, reject) => {
      const waiter: GateWaiter = { resolve, reject };
      if (deadline !== undefined) {
        waiter.timer = setTimeout(() => {
          const index = this.waiters.indexOf(waiter);
          if (index < 0) return;
          this.waiters.splice(index, 1);
          reject(new Error('OBJECT_STORAGE_TIMEOUT'));
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
    }
    else this.active -= 1;
  }
}

export function createTimeoutTransport(
  transport: Pick<typeof http, 'request'>,
  timeoutMs: number,
): Pick<typeof http, 'request'> {
  const request = ((...args: any[]) => {
    const outgoing = (transport.request as (...requestArgs: any[]) => http.ClientRequest)(...args);
    const timeoutError = () => new Error('OBJECT_STORAGE_TIMEOUT');
    const headerTimer = setTimeout(() => outgoing.destroy(timeoutError()), timeoutMs);
    headerTimer.unref();
    outgoing.setTimeout(timeoutMs, () => outgoing.destroy(timeoutError()));
    const finishRequest = () => {
      clearTimeout(headerTimer);
      outgoing.setTimeout(0);
    };
    outgoing.once('error', finishRequest);
    outgoing.once('response', (response) => {
      finishRequest();
      response.setTimeout(timeoutMs, () => response.destroy(timeoutError()));
      // IncomingMessage clears its public `socket` reference after end; retain
      // the actual socket so cleanup cannot dereference null on newer Node.
      const responseSocket = response.socket;
      const finishResponse = () => responseSocket?.setTimeout(0);
      response.once('end', finishResponse);
      response.once('close', finishResponse);
      response.once('error', finishResponse);
    });
    return outgoing;
  }) as typeof http.request;
  return { request };
}

const minioClient = new Minio.Client({
  endPoint: config.minio.endPoint,
  port: config.minio.port,
  useSSL: config.minio.useSSL,
  accessKey: config.minio.accessKey,
  secretKey: config.minio.secretKey,
  transport: createTimeoutTransport(config.minio.useSSL ? https : http, config.minio.requestTimeoutMs),
  retryOptions: { disableRetry: true },
});

const objectStorageGate = new BoundedAsyncGate(
  MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS,
  MAX_PENDING_OBJECT_STORAGE_OPERATIONS,
);

export function createObjectStorageDeadline(): number {
  return Date.now() + config.minio.requestTimeoutMs;
}

async function withObjectStorageDeadline<T>(
  operation: () => Promise<T>,
  deadline = createObjectStorageDeadline(),
): Promise<T> {
  if (deadline <= Date.now()) throw new Error('OBJECT_STORAGE_TIMEOUT');
  // The gate removes work that expires before it starts. Once remote mutation
  // begins, wait for the transport-enforced timeout/success before returning so
  // a per-upload lock can never release while stale I/O is still running.
  const result = await objectStorageGate.run(operation, deadline);
  if (Date.now() > deadline) throw new Error('OBJECT_STORAGE_TIMEOUT');
  return result;
}

let bucketPromise: Promise<void> | null = null;

export async function ensureObjectStorageBucket(): Promise<void> {
  bucketPromise ||= withObjectStorageDeadline(async () => {
    if (!await minioClient.bucketExists(config.minio.bucket)) {
      try {
        await minioClient.makeBucket(config.minio.bucket);
      } catch (error: any) {
        if (error?.code !== 'BucketAlreadyOwnedByYou' && error?.code !== 'BucketAlreadyExists') throw error;
      }
    }
  }).catch((error: unknown) => {
    bucketPromise = null;
    throw error;
  });
  await bucketPromise;
}

export async function checkObjectStorage(): Promise<void> {
  await ensureObjectStorageBucket();
  await statStoredObject('.alparts-healthcheck').catch((error: any) => {
    // A missing sentinel proves the bucket is reachable without mutating it.
    if (error?.code !== 'NotFound' && error?.code !== 'NoSuchKey') throw error;
  });
}

export function statStoredObject(storageKey: string, deadline?: number) {
  return withObjectStorageDeadline(
    () => minioClient.statObject(config.minio.bucket, storageKey),
    deadline,
  );
}

export function putStoredObject(storageKey: string, body: Buffer) {
  return withObjectStorageDeadline(() => minioClient.putObject(
    config.minio.bucket,
    storageKey,
    body,
    body.length,
    { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' },
  ));
}

export async function getStoredObject(storageKey: string): Promise<Readable> {
  const deadline = createObjectStorageDeadline();
  const release = await objectStorageGate.acquireLease(deadline);
  try {
    const stream = await minioClient.getObject(config.minio.bucket, storageKey);
    if (Date.now() >= deadline) {
      stream.destroy(new Error('OBJECT_STORAGE_TIMEOUT'));
      throw new Error('OBJECT_STORAGE_TIMEOUT');
    }
    const timer = setTimeout(() => stream.destroy(new Error('OBJECT_STORAGE_TIMEOUT')), deadline - Date.now());
    timer.unref();
    const finish = () => {
      clearTimeout(timer);
      release();
    };
    stream.once('end', finish);
    stream.once('close', finish);
    stream.once('error', finish);
    return stream;
  } catch (error) {
    release();
    throw error;
  }
}

export async function deleteStoredUpload(storagePrefix: string): Promise<void> {
  await withObjectStorageDeadline(async () => {
    const objectNames = new Set(await listObjectNames(`${storagePrefix}/`));
    // Also clean reservations created before the chunk-attempt protocol.
    objectNames.add(storagePrefix);
    const results = await minioClient.removeObjects(config.minio.bucket, [...objectNames]);
    if (results.some(Boolean)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
  });
}

export async function reconcileStoredUpload(
  storagePrefix: string,
  expected: ReadonlySet<string>,
): Promise<void> {
  await withObjectStorageDeadline(async () => {
    const unexpected = (await listObjectNames(`${storagePrefix}/`)).filter((name) => !expected.has(name));
    if (unexpected.length === 0) return;
    const results = await minioClient.removeObjects(config.minio.bucket, unexpected);
    if (results.some(Boolean)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
  });
}

export async function removeStoredObjectBestEffort(storageKey: string): Promise<void> {
  await withObjectStorageDeadline(() => minioClient.removeObject(config.minio.bucket, storageKey)).catch(() => undefined);
}

export function isObjectStorageTimeout(error: unknown): error is Error {
  return error instanceof Error && error.message === 'OBJECT_STORAGE_TIMEOUT';
}

function listObjectNames(prefix: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const names: string[] = [];
    const stream = minioClient.listObjectsV2(config.minio.bucket, prefix, true);
    stream.on('data', (item) => {
      if (item.name) names.push(item.name);
    });
    stream.on('error', reject);
    stream.on('end', () => resolve(names));
  });
}
