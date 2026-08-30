import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type * as http from 'node:http';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';

const noncePrefix = Buffer.alloc(8, 7).toString('base64');

describe('fixed attachment chunk contract', () => {
  it('accepts exact single, multi-chunk, empty, and maximum-size layouts', async () => {
    const service = await import('./attachment-contract.js');
    const single = manifest(123);
    assert.deepEqual(
      service.validateFinalChunkLayout(1, single, [{ chunkIndex: 0, sizeBytes: 123 + service.ATTACHMENT_GCM_TAG_BYTES }]),
      { ciphertextSizeBytes: 139, plaintextSizeBytes: 123 },
    );

    const multiPlaintext = service.ATTACHMENT_PLAINTEXT_CHUNK_BYTES + 91;
    assert.deepEqual(service.validateFinalChunkLayout(2, manifest(multiPlaintext), [
      { chunkIndex: 0, sizeBytes: service.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES },
      { chunkIndex: 1, sizeBytes: 91 + service.ATTACHMENT_GCM_TAG_BYTES },
    ]), {
      ciphertextSizeBytes: multiPlaintext + 2 * service.ATTACHMENT_GCM_TAG_BYTES,
      plaintextSizeBytes: multiPlaintext,
    });

    assert.deepEqual(
      service.validateFinalChunkLayout(1, manifest(0), [{ chunkIndex: 0, sizeBytes: service.ATTACHMENT_GCM_TAG_BYTES }]),
      { ciphertextSizeBytes: service.ATTACHMENT_GCM_TAG_BYTES, plaintextSizeBytes: 0 },
    );

    const maximum = Array.from({ length: service.MAX_ATTACHMENT_CHUNKS }, (_, chunkIndex) => ({
      chunkIndex,
      sizeBytes: service.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES,
    }));
    assert.equal(
      service.validateFinalChunkLayout(service.MAX_ATTACHMENT_CHUNKS, manifest(100 * 1024 * 1024), maximum).plaintextSizeBytes,
      100 * 1024 * 1024,
    );
  });

  it('rejects gaps, short non-final chunks, oversized final chunks, and manifest mismatches', async () => {
    const service = await import('./attachment-contract.js');
    const twoChunkSize = service.ATTACHMENT_PLAINTEXT_CHUNK_BYTES + 1;
    const exactRows = [
      { chunkIndex: 0, sizeBytes: service.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES },
      { chunkIndex: 1, sizeBytes: service.ATTACHMENT_GCM_TAG_BYTES + 1 },
    ];
    assert.throws(
      () => service.validateFinalChunkLayout(2, manifest(twoChunkSize), [exactRows[1], exactRows[0]]),
      /INVALID_CHUNK_LAYOUT/,
    );
    assert.throws(
      () => service.validateFinalChunkLayout(2, manifest(twoChunkSize), [
        { chunkIndex: 0, sizeBytes: service.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES - 1 },
        exactRows[1],
      ]),
      /INVALID_CHUNK_SIZE/,
    );
    assert.throws(
      () => service.validateFinalChunkLayout(1, manifest(service.ATTACHMENT_PLAINTEXT_CHUNK_BYTES + 1), [
        { chunkIndex: 0, sizeBytes: service.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES + 1 },
      ]),
      /INVALID_CHUNK_SIZE/,
    );
    assert.throws(
      () => service.validateFinalChunkLayout(2, manifest(twoChunkSize + 1), exactRows),
      /INVALID_CHUNK_LAYOUT/,
    );
    assert.throws(
      () => service.validateFinalChunkLayout(1, manifest(twoChunkSize), [exactRows[0]]),
      /INVALID_CHUNK_LAYOUT/,
    );
    assert.throws(
      () => service.validateFinalChunkLayout(2, manifest(twoChunkSize), [exactRows[0]]),
      /INVALID_CHUNK_LAYOUT/,
    );
  });

  it('requires the fixed AES-GCM manifest and canonical eight-byte nonce prefix', async () => {
    const service = await import('./attachment-contract.js');
    assert.doesNotThrow(() => service.assertValidManifest(manifest(1)));
    assert.throws(
      () => service.assertValidManifest({ ...manifest(1), noncePrefix: Buffer.alloc(7).toString('base64') }),
      /INVALID_CRYPTO_MANIFEST/,
    );
    assert.throws(
      () => service.assertValidManifest({ ...manifest(1), algorithm: 'AES-128-GCM' } as any),
      /INVALID_CRYPTO_MANIFEST/,
    );
    assert.throws(
      () => service.assertValidManifest({ ...manifest(1), plaintextSize: 100 * 1024 * 1024 + 1 }),
      /INVALID_CRYPTO_MANIFEST/,
    );
  });

  it('uses opaque fixed-width object keys and marks active document types as dangerous', async () => {
    const service = await import('./attachment-contract.js');
    const key = service.attachmentChunkStorageKey('attachments/v1/opaque-random-prefix', 12);
    assert.equal(key, 'attachments/v1/opaque-random-prefix/000012');
    assert.equal(
      service.attachmentChunkStorageKey(
        'attachments/v1/opaque-random-prefix',
        12,
        '11111111-1111-4111-8111-111111111111',
      ),
      'attachments/v1/opaque-random-prefix/000012/11111111-1111-4111-8111-111111111111',
    );
    assert.equal(key.includes('message-id'), false);
    assert.equal(service.isDangerousAttachmentMime('text/html'), true);
    assert.equal(service.isDangerousAttachmentMime('image/svg+xml'), true);
    assert.equal(service.isDangerousAttachmentMime('application/pdf'), true);
    assert.equal(service.isDangerousAttachmentMime('image/png'), false);
  });

  it('applies the object-storage timeout before headers and to response-stream inactivity', async () => {
    const service = await import('./object-storage.js');
    const firstRequest = new FakeRequest();
    const transport = service.createTimeoutTransport({
      request: (() => firstRequest as unknown as http.ClientRequest) as typeof http.request,
    }, 1_000);
    transport.request({});
    assert.equal(firstRequest.timeoutMs, 1_000);
    firstRequest.timeoutCallback?.();
    assert.equal(firstRequest.destroyedWith?.message, 'OBJECT_STORAGE_TIMEOUT');

    const secondRequest = new FakeRequest();
    const streamTransport = service.createTimeoutTransport({
      request: (() => secondRequest as unknown as http.ClientRequest) as typeof http.request,
    }, 2_000);
    streamTransport.request({});
    const response = new FakeResponse();
    secondRequest.emit('response', response);
    assert.equal(secondRequest.timeoutMs, 0);
    assert.equal(response.timeoutMs, 2_000);
    response.timeoutCallback?.();
    assert.equal(response.destroyedWith?.message, 'OBJECT_STORAGE_TIMEOUT');
  });

  it('serializes remote phases for one upload without blocking a different upload', async () => {
    const service = await import('./file.service.js');
    const events: string[] = [];
    let releaseFirst!: () => void;
    let firstEntered!: () => void;
    const entered = new Promise<void>((resolve) => { firstEntered = resolve; });
    const gate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const first = service.withUploadOperationLock('upload-a', async () => {
      events.push('first:start');
      firstEntered();
      await gate;
      events.push('first:end');
    });
    await entered;
    const second = service.withUploadOperationLock('upload-a', async () => {
      events.push('second');
    });
    const independent = service.withUploadOperationLock('upload-b', async () => {
      events.push('independent');
    });
    await independent;
    assert.deepEqual(events, ['first:start', 'independent']);
    releaseFirst();
    await Promise.all([first, second]);
    assert.deepEqual(events, ['first:start', 'independent', 'first:end', 'second']);
  });

  it('bounds the per-upload serialization queue', async () => {
    const service = await import('./file.service.js');
    let releaseFirst!: () => void;
    const firstBarrier = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const first = service.withUploadOperationLock('bounded-upload', async () => firstBarrier);
    const queued = Array.from(
      { length: service.MAX_UPLOAD_OPERATIONS_PER_UPLOAD - 1 },
      () => service.withUploadOperationLock('bounded-upload', async () => undefined),
    );
    await assert.rejects(
      service.withUploadOperationLock('bounded-upload', async () => undefined),
      /UPLOAD_OPERATION_BUSY/,
    );
    releaseFirst();
    await Promise.all([first, ...queued]);
  });

  it('bounds active and pending object-storage work and releases capacity exactly', async () => {
    const { BoundedAsyncGate } = await import('./object-storage.js');
    const gate = new BoundedAsyncGate(1, 1, {
      busyError: 'OBJECT_STORAGE_BUSY', timeoutError: 'OBJECT_STORAGE_TIMEOUT',
    });
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const first = gate.run(async () => blocked);
    const second = gate.run(async () => 'second');
    await assert.rejects(gate.run(async () => 'overflow'), /OBJECT_STORAGE_BUSY/);
    release();
    assert.deepEqual(await Promise.all([first, second]), [undefined, 'second']);
    assert.equal(await gate.run(async () => 'reused'), 'reused');
  });

  it('holds explicit object-storage leases until the caller releases them', async () => {
    const { BoundedAsyncGate } = await import('./object-storage.js');
    const gate = new BoundedAsyncGate(1, 0, {
      busyError: 'OBJECT_STORAGE_BUSY', timeoutError: 'OBJECT_STORAGE_TIMEOUT',
    });
    const release = await gate.acquireLease();
    await assert.rejects(gate.acquireLease(), /OBJECT_STORAGE_BUSY/);
    release();
    release();
    const replacement = await gate.acquireLease();
    replacement();
  });

  it('caps concurrent download streams per user and globally', async () => {
    const { DownloadLeaseState } = await import('../security/download-limits.js');
    const state = new DownloadLeaseState(1, 2);
    const first = state.acquire('user-a');
    assert.equal(typeof first, 'function');
    assert.equal(state.acquire('user-a'), null);
    const second = state.acquire('user-b');
    assert.equal(typeof second, 'function');
    assert.equal(state.acquire('user-c'), null);
    first?.();
    first?.();
    const replacement = state.acquire('user-a');
    assert.equal(typeof replacement, 'function');
    second?.();
    replacement?.();
  });

  it('removes an expired queued operation instead of running it later', async () => {
    const { BoundedAsyncGate } = await import('./object-storage.js');
    const gate = new BoundedAsyncGate(1, 1, {
      busyError: 'OBJECT_STORAGE_BUSY', timeoutError: 'OBJECT_STORAGE_TIMEOUT',
    });
    let release!: () => void;
    let staleOperationRan = false;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const first = gate.run(async () => blocked);
    const expired = gate.run(async () => {
      staleOperationRan = true;
    }, Date.now() + 20);

    await assert.rejects(expired, /OBJECT_STORAGE_TIMEOUT/);
    release();
    await first;
    await new Promise((resolve) => setTimeout(resolve, 0));

    assert.equal(staleOperationRan, false);
    assert.equal(await gate.run(async () => 'reused'), 'reused');
  });

  it('stops materializing an object listing after the per-upload bound', async () => {
    const { collectBoundedObjectNames } = await import('./object-storage.js');
    const stream = new FakeListingStream();
    const result = collectBoundedObjectNames(stream, 2);
    stream.emit('data', { name: 'prefix/000000' });
    stream.emit('data', { name: 'prefix/000001' });
    stream.emit('data', { name: 'prefix/attacker-extra' });
    await assert.rejects(result, /OBJECT_STORAGE_LIST_LIMIT/);
    assert.equal(stream.destroyedWith?.message, 'OBJECT_STORAGE_LIST_LIMIT');
  });

  it('rejects oversized and out-of-prefix object keys without retaining them', async () => {
    const { collectBoundedObjectNames, MAX_OBJECT_KEY_BYTES } = await import('./object-storage.js');
    const oversized = new FakeListingStream();
    const oversizedResult = collectBoundedObjectNames(oversized, 2);
    oversized.emit('data', { name: 'x'.repeat(MAX_OBJECT_KEY_BYTES + 1) });
    await assert.rejects(oversizedResult, /OBJECT_STORAGE_LIST_LIMIT/);

    const foreign = new FakeListingStream();
    const foreignResult = collectBoundedObjectNames(
      foreign,
      2,
      Date.now() + 1_000,
      'attachments/v1/expected/',
    );
    foreign.emit('data', { name: 'attachments/v1/other/000000' });
    await assert.rejects(foreignResult, /OBJECT_STORAGE_LIST_INVALID_KEY/);
  });

  it('enforces an absolute listing deadline even while entries keep arriving', async () => {
    const { collectBoundedObjectNames } = await import('./object-storage.js');
    const stream = new FakeListingStream();
    const result = collectBoundedObjectNames(stream, 100, Date.now() + 25);
    let index = 0;
    const activity = setInterval(() => stream.emit('data', { name: `prefix/${index++}` }), 2);
    try {
      await assert.rejects(result, /OBJECT_STORAGE_TIMEOUT/);
    } finally {
      clearInterval(activity);
    }
    assert.equal(stream.destroyedWith?.message, 'OBJECT_STORAGE_TIMEOUT');
  });
});

class FakeListingStream extends EventEmitter {
  destroyedWith: Error | undefined;

  destroy(error?: Error) {
    this.destroyedWith = error;
    return this;
  }
}

class FakeRequest extends EventEmitter {
  timeoutMs = -1;
  timeoutCallback: (() => void) | undefined;
  destroyedWith: Error | undefined;

  setTimeout(timeoutMs: number, callback?: () => void) {
    this.timeoutMs = timeoutMs;
    this.timeoutCallback = callback;
    return this;
  }

  destroy(error?: Error) {
    this.destroyedWith = error;
    if (error) this.emit('error', error);
    return this;
  }
}

class FakeResponse extends EventEmitter {
  timeoutMs = -1;
  timeoutCallback: (() => void) | undefined;
  destroyedWith: Error | undefined;

  setTimeout(timeoutMs: number, callback?: () => void) {
    this.timeoutMs = timeoutMs;
    this.timeoutCallback = callback;
    return this;
  }

  destroy(error?: Error) {
    this.destroyedWith = error;
    if (error) this.emit('error', error);
    this.emit('close');
    return this;
  }
}

function manifest(plaintextSize: number) {
  return {
    version: 1 as const,
    algorithm: 'AES-256-GCM' as const,
    nonceStrategy: 'prefix-counter-be32' as const,
    noncePrefix,
    aadVersion: 1 as const,
    plaintextSize,
  };
}
