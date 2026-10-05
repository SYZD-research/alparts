import { createHash } from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import { Readable } from 'node:stream';
import {
  CreateBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
  paginateListObjectsV2,
} from '@aws-sdk/client-s3';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { config } from '../config/index.js';
import { BoundedAsyncGate } from '../security/bounded-async-gate.js';
import { MAX_ATTACHMENT_CHUNKS } from './attachment-contract.js';

export { BoundedAsyncGate } from '../security/bounded-async-gate.js';

export const MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS = 8;
export const MAX_PENDING_OBJECT_STORAGE_OPERATIONS = 32;
const MAX_KEYS_PER_DELETE_REQUEST = 1_000;

/** A URL host component; an IPv6 literal needs brackets. */
export function objectStorageEndpoint(host: string, port: number, useSSL: boolean): string {
  const bracketed = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return `${useSSL ? 'https' : 'http'}://${bracketed}:${port}`;
}

/**
 * An abort signal for an absolute deadline. A peer that keeps trickling
 * headers, listing pages or body bytes cannot hold a request past it.
 */
export function objectStorageDeadlineSignal(deadline: number): AbortSignal {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('OBJECT_STORAGE_TIMEOUT')), Math.max(0, deadline - Date.now()));
  timer.unref();
  controller.signal.addEventListener('abort', () => clearTimeout(timer), { once: true });
  return controller.signal;
}

const s3Client = new S3Client({
  endpoint: objectStorageEndpoint(config.s3.endpoint, config.s3.port, config.s3.useSSL),
  region: config.s3.region,
  forcePathStyle: true,
  credentials: { accessKeyId: config.s3.accessKey, secretAccessKey: config.s3.secretKey },
  // Retrying is the caller's decision; a retry must not outlive the deadline.
  maxAttempts: 1,
  // S3-compatible stores do not all accept the SDK's newer default checksums.
  requestChecksumCalculation: 'WHEN_REQUIRED',
  responseChecksumValidation: 'WHEN_REQUIRED',
  requestHandler: new NodeHttpHandler({
    connectionTimeout: config.s3.requestTimeoutMs,
    requestTimeout: config.s3.requestTimeoutMs,
    // Without this the SDK only logs an idle request instead of failing it.
    throwOnRequestTimeout: true,
    httpAgent: new http.Agent({ keepAlive: true, maxSockets: MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS }),
    httpsAgent: new https.Agent({ keepAlive: true, maxSockets: MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS }),
  }),
});

/** Run one S3 command under an absolute deadline. */
async function send<T>(
  operation: (options: { abortSignal: AbortSignal }) => Promise<T>,
  deadline: number,
): Promise<T> {
  const abortSignal = objectStorageDeadlineSignal(deadline);
  try {
    return await operation({ abortSignal });
  } catch (error) {
    if (abortSignal.aborted) throw new Error('OBJECT_STORAGE_TIMEOUT');
    throw error;
  }
}

/**
 * The store checks the bytes it received against this digest, so a body
 * damaged on the way is refused instead of being stored and acknowledged.
 */
function bodyDigests(body: Buffer): { base64: string; hex: string } {
  const digest = createHash('md5').update(body).digest();
  return { base64: digest.toString('base64'), hex: digest.toString('hex') };
}

/** A plain-upload ETag is the body's MD5; one that differs means other bytes were stored. */
function assertStoredDigest(etag: string | undefined, expectedHex: string): void {
  const normalized = (etag ?? '').replace(/^"|"$/g, '').trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(normalized) && normalized !== expectedHex) throw new Error('OBJECT_STORAGE_INTEGRITY');
}

function isNotFound(error: unknown): boolean {
  const failure = error as { name?: string; $metadata?: { httpStatusCode?: number } } | null;
  return ['NoSuchKey', 'NotFound', 'NoSuchBucket'].includes(failure?.name ?? '')
    || failure?.$metadata?.httpStatusCode === 404;
}

const objectStorageGate = new BoundedAsyncGate(
  MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS,
  MAX_PENDING_OBJECT_STORAGE_OPERATIONS,
  { busyError: 'OBJECT_STORAGE_BUSY', timeoutError: 'OBJECT_STORAGE_TIMEOUT' },
);

export function objectStorageWorkSnapshot() {
  return objectStorageGate.snapshot();
}

export function createObjectStorageDeadline(): number {
  return Date.now() + config.s3.requestTimeoutMs;
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
  const deadline = createObjectStorageDeadline();
  bucketPromise ||= withObjectStorageDeadline(async () => {
    if (!await bucketExists(config.s3.bucket, deadline)) {
      try {
        await send((options) => s3Client.send(new CreateBucketCommand({ Bucket: config.s3.bucket }), options), deadline);
      } catch (error: any) {
        if (error?.name !== 'BucketAlreadyOwnedByYou' && error?.name !== 'BucketAlreadyExists') throw error;
      }
    }
  }, deadline).catch((error: unknown) => {
    bucketPromise = null;
    throw error;
  });
  await bucketPromise;
}

export async function checkObjectStorage(): Promise<void> {
  await ensureObjectStorageBucket();
  await statStoredObject('.alparts-healthcheck').catch((error: unknown) => {
    // A missing sentinel proves the bucket is reachable without mutating it.
    if (!isNotFound(error)) throw error;
  });
}

/** Operator-only provisioning; normal audit reads/writes never recreate a missing head. */
export async function provisionAuditHeadBucket(): Promise<void> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  const deadline = createObjectStorageDeadline();
  await withObjectStorageDeadline(async () => {
    if (!await bucketExists(config.audit.headBucket, deadline)) {
      await send((options) => s3Client.send(new CreateBucketCommand({ Bucket: config.audit.headBucket }), options), deadline);
    }
  }, deadline);
}

export async function readStoredAuditHead(): Promise<string | null> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  const deadline = createObjectStorageDeadline();
  return withObjectStorageDeadline(async () => {
    let stream: Readable;
    try {
      stream = await getObjectStream(config.audit.headBucket, config.audit.headObjectKey!, deadline);
    } catch (error) {
      if (isNotFound(error)) return null;
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
  }, deadline);
}

export async function writeStoredAuditHead(serialized: string): Promise<void> {
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  const body = Buffer.from(serialized);
  const digests = bodyDigests(body);
  const deadline = createObjectStorageDeadline();
  await withObjectStorageDeadline(async () => {
    const result = await send((options) => s3Client.send(new PutObjectCommand({
      Bucket: config.audit.headBucket,
      Key: config.audit.headObjectKey!,
      Body: body,
      ContentLength: body.byteLength,
      ContentMD5: digests.base64,
      ContentType: 'application/json',
      CacheControl: 'no-store',
    }), options), deadline);
    assertStoredDigest(result.ETag, digests.hex);
  }, deadline);
}

export function statStoredObject(storageKey: string, deadline = createObjectStorageDeadline()): Promise<{ size: number; etag: string }> {
  return withObjectStorageDeadline(async () => {
    const head = await send(
      (options) => s3Client.send(new HeadObjectCommand({ Bucket: config.s3.bucket, Key: storageKey }), options),
      deadline,
    );
    return { size: head.ContentLength ?? -1, etag: head.ETag ?? '' };
  }, deadline);
}

export function putStoredObject(storageKey: string, body: Buffer): Promise<{ etag: string }> {
  const digests = bodyDigests(body);
  const deadline = createObjectStorageDeadline();
  return withObjectStorageDeadline(async () => {
    const result = await send((options) => s3Client.send(new PutObjectCommand({
      Bucket: config.s3.bucket,
      Key: storageKey,
      Body: body,
      ContentLength: body.byteLength,
      ContentMD5: digests.base64,
      ContentType: 'application/octet-stream',
      CacheControl: 'no-store',
    }), options), deadline);
    assertStoredDigest(result.ETag, digests.hex);
    return { etag: result.ETag ?? '' };
  }, deadline);
}

async function bucketExists(bucket: string, deadline: number): Promise<boolean> {
  try {
    await send((options) => s3Client.send(new HeadBucketCommand({ Bucket: bucket }), options), deadline);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}

/** The response body stays bound to the deadline after the headers arrive. */
async function getObjectStream(bucket: string, key: string, deadline: number): Promise<Readable> {
  const result = await send((options) => s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }), options), deadline);
  if (!(result.Body instanceof Readable)) throw new Error('OBJECT_STORAGE_INVALID_RESPONSE');
  return result.Body;
}

/** Delete keys in bounded batches; any per-key failure is reported. */
async function removeObjects(keys: string[], deadline: number): Promise<boolean> {
  for (let offset = 0; offset < keys.length; offset += MAX_KEYS_PER_DELETE_REQUEST) {
    const batch = keys.slice(offset, offset + MAX_KEYS_PER_DELETE_REQUEST);
    const result = await send((options) => s3Client.send(new DeleteObjectsCommand({
      Bucket: config.s3.bucket,
      Delete: { Objects: batch.map((Key) => ({ Key })), Quiet: true },
    }), options), deadline);
    if (result.Errors?.length) return false;
  }
  return true;
}

export async function getStoredObject(storageKey: string): Promise<Readable> {
  const deadline = createObjectStorageDeadline();
  const release = await objectStorageGate.acquireLease(deadline);
  try {
    const stream = await getObjectStream(config.s3.bucket, storageKey, deadline);
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
    if (!await removeObjects([...objectNames], deadline)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
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
    if (!await removeObjects(unexpected, deadline)) throw new Error('ORPHAN_CHUNK_DELETE_FAILED');
  }, deadline);
}

export async function removeStoredObjectBestEffort(storageKey: string): Promise<void> {
  const deadline = createObjectStorageDeadline();
  await withObjectStorageDeadline(
    () => send((options) => s3Client.send(new DeleteObjectCommand({ Bucket: config.s3.bucket, Key: storageKey }), options), deadline),
    deadline,
  ).catch(() => undefined);
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

/** Page through a listing as a stream, so the bounded collector can stop it early. */
function listObjectNames(prefix: string, deadline: number): Promise<string[]> {
  const abortSignal = objectStorageDeadlineSignal(deadline);
  const pages = paginateListObjectsV2(
    { client: s3Client, pageSize: MAX_KEYS_PER_DELETE_REQUEST },
    { Bucket: config.s3.bucket, Prefix: prefix },
    { abortSignal },
  );
  const names = Readable.from((async function* () {
    for await (const page of pages) {
      for (const object of page.Contents ?? []) yield { name: object.Key };
    }
  })());
  // The request abort and the collector's own deadline fire together; either
  // way the caller sees one storage timeout.
  return collectBoundedObjectNames(names, undefined, deadline, prefix).catch((error: unknown) => {
    if (abortSignal.aborted) throw new Error('OBJECT_STORAGE_TIMEOUT');
    throw error;
  });
}
