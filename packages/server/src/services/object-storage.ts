import * as http from 'node:http';
import * as https from 'node:https';
import * as Minio from 'minio';
import { config } from '../config/index.js';
import type { Readable } from 'node:stream';
import { BoundedAsyncGate } from '../security/bounded-async-gate.js';
import { MAX_ATTACHMENT_CHUNKS } from './attachment-contract.js';

export { BoundedAsyncGate } from '../security/bounded-async-gate.js';

export const MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS = 8;
export const MAX_PENDING_OBJECT_STORAGE_OPERATIONS = 32;

export function createTimeoutTransport(
  transport: Pick<typeof http, 'request'>,
  timeoutMs: number,
): Pick<typeof http, 'request'> {
  const request = ((...args: any[]) => {
    const outgoing = (transport.request as (...requestArgs: any[]) => http.ClientRequest)(...args);
    const timeoutError = () => new Error('OBJECT_STORAGE_TIMEOUT');
    let incoming: http.IncomingMessage | null = null;
    // This is an absolute request deadline, not only an idle-socket timeout.
    // A peer that continuously trickles headers or listing entries therefore
    // cannot retain a gate lease forever.
    const operationTimer = setTimeout(() => {
      const error = timeoutError();
      incoming?.destroy(error);
      outgoing.destroy(error);
    }, timeoutMs);
    operationTimer.unref();
    outgoing.setTimeout(timeoutMs, () => outgoing.destroy(timeoutError()));
    const finishOperation = () => {
      clearTimeout(operationTimer);
      outgoing.setTimeout(0);
    };
    outgoing.once('error', finishOperation);
    outgoing.once('response', (response) => {
      incoming = response;
      outgoing.setTimeout(0);
      response.setTimeout(timeoutMs, () => response.destroy(timeoutError()));
      // IncomingMessage clears its public `socket` reference after end; retain
      // the actual socket so cleanup cannot dereference null on newer Node.
      const responseSocket = response.socket;
      const finishResponse = () => responseSocket?.setTimeout(0);
      const finish = () => {
        finishOperation();
        finishResponse();
      };
      response.once('end', finish);
      response.once('close', finish);
      response.once('error', finish);
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
  { busyError: 'OBJECT_STORAGE_BUSY', timeoutError: 'OBJECT_STORAGE_TIMEOUT' },
);

export function objectStorageWorkSnapshot() {
  return objectStorageGate.snapshot();
}

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

/** Operator-only provisioning; normal audit reads/writes never recreate a missing head. */
export async function provisionAuditHeadBucket(): Promise<void> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  await withObjectStorageDeadline(async () => {
    if (!await minioClient.bucketExists(config.audit.headBucket)) {
      await minioClient.makeBucket(config.audit.headBucket);
    }
  });
}

export async function readStoredAuditHead(): Promise<string | null> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  return withObjectStorageDeadline(async () => {
    let stream: Readable;
    try {
      stream = await minioClient.getObject(config.audit.headBucket, config.audit.headObjectKey!);
    } catch (error: any) {
      if (['NoSuchKey', 'NoSuchBucket', 'NotFound'].includes(error?.code)) return null;
      throw error;
    }
    const chunks: Buffer[] = [];
    let length = 0;
    try {
      for await (const part of stream) {
        const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
        length += chunk.length;
        if (length > 16 * 1024) throw new Error('INVALID_AUDIT_HEAD');
        chunks.push(chunk);
      }
      return Buffer.concat(chunks).toString('utf8');
    } finally { stream.destroy(); }
  });
}

export async function writeStoredAuditHead(serialized: string): Promise<void> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  const body = Buffer.from(serialized);
  await withObjectStorageDeadline(() => minioClient.putObject(
    config.audit.headBucket, config.audit.headObjectKey!, body, body.length,
    { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  ));
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
  const deadline = createObjectStorageDeadline();
  await withObjectStorageDeadline(async () => {
    const objectNames = new Set(await listObjectNames(`${storagePrefix}/`, deadline));
    // Also clean reservations created before the chunk-attempt protocol.
    objectNames.add(storagePrefix);
    const results = await minioClient.removeObjects(config.minio.bucket, [...objectNames]);
    if (results.some(Boolean)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
  }, deadline);
}

export async function reconcileStoredUpload(
  storagePrefix: string,
  expected: ReadonlySet<string>,
): Promise<void> {
  const deadline = createObjectStorageDeadline();
  await withObjectStorageDeadline(async () => {
    const unexpected = (await listObjectNames(`${storagePrefix}/`, deadline)).filter((name) => !expected.has(name));
    if (unexpected.length === 0) return;
    const results = await minioClient.removeObjects(config.minio.bucket, unexpected);
    if (results.some(Boolean)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
  }, deadline);
}

export async function removeStoredObjectBestEffort(storageKey: string): Promise<void> {
  await withObjectStorageDeadline(() => minioClient.removeObject(config.minio.bucket, storageKey)).catch(() => undefined);
}

export function isObjectStorageTimeout(error: unknown): error is Error {
  return error instanceof Error && error.message === 'OBJECT_STORAGE_TIMEOUT';
}

// A valid upload has one authoritative object per chunk. The extra allowance
// covers failed replacement attempts while keeping cleanup work and memory
// bounded even when the object-store endpoint is malicious.
export const MAX_OBJECTS_PER_UPLOAD_PREFIX = MAX_ATTACHMENT_CHUNKS * 16 + 1;
export const MAX_OBJECT_KEY_BYTES = 1_024;
export const MAX_LISTED_OBJECT_KEY_BYTES = MAX_OBJECTS_PER_UPLOAD_PREFIX * MAX_OBJECT_KEY_BYTES;

export function collectBoundedObjectNames(
  stream: NodeJS.EventEmitter & { destroy?: (error?: Error) => unknown },
  limit = MAX_OBJECTS_PER_UPLOAD_PREFIX,
  deadline = createObjectStorageDeadline(),
  expectedPrefix?: string,
): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const names: string[] = [];
    let retainedBytes = 0;
    let settled = false;
    const timer = setTimeout(() => {
      const error = new Error('OBJECT_STORAGE_TIMEOUT');
      stream.destroy?.(error);
      fail(error);
    }, Math.max(0, deadline - Date.now()));
    timer.unref();
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error instanceof Error ? error : new Error('OBJECT_STORAGE_LIST_FAILED'));
    };
    stream.on('data', (item: { name?: string }) => {
      if (settled || !item.name) return;
      if (expectedPrefix) {
        const suffix = item.name.startsWith(expectedPrefix) ? item.name.slice(expectedPrefix.length) : '';
        if (!/^[0-9]{6}(?:\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})?$/.test(suffix)) {
          const error = new Error('OBJECT_STORAGE_LIST_INVALID_KEY');
          stream.destroy?.(error);
          fail(error);
          return;
        }
      }
      const keyBytes = Buffer.byteLength(item.name, 'utf8');
      if (keyBytes > MAX_OBJECT_KEY_BYTES || retainedBytes + keyBytes > MAX_LISTED_OBJECT_KEY_BYTES) {
        const error = new Error('OBJECT_STORAGE_LIST_LIMIT');
        stream.destroy?.(error);
        fail(error);
        return;
      }
      names.push(item.name);
      retainedBytes += keyBytes;
      if (names.length > limit) {
        const error = new Error('OBJECT_STORAGE_LIST_LIMIT');
        stream.destroy?.(error);
        fail(error);
      }
    });
    stream.on('error', fail);
    stream.on('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(names);
    });
  });
}

function listObjectNames(prefix: string, deadline: number): Promise<string[]> {
  return collectBoundedObjectNames(
    minioClient.listObjectsV2(config.minio.bucket, prefix, true),
    undefined,
    deadline,
    prefix,
  );
}
