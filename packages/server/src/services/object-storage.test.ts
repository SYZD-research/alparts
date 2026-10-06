import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { after, before, describe, it } from 'node:test';

// A minimal S3 endpoint: it records uploads, can answer with a chosen ETag,
// never answers listings so their deadline can be observed, and starts but
// never finishes downloads under stalled/ so they hold their storage slots.
const uploads: Array<{ headers: IncomingMessage['headers']; body: Buffer }> = [];
let etagOverride: string | null = null;
const listingRequests = new Map<string, number>();
let bucketPresent = true;
let pageToken = 0;

function listingPage(contents: string, nextToken: string | null): string {
  return '<?xml version="1.0" encoding="UTF-8"?>'
    + '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>alparts</Name><MaxKeys>1000</MaxKeys>'
    + `<IsTruncated>${nextToken ? 'true' : 'false'}</IsTruncated>`
    + (nextToken ? `<NextContinuationToken>${nextToken}</NextContinuationToken>` : '')
    + `${contents}</ListBucketResult>`;
}
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const chunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => chunks.push(chunk));
  req.on('end', () => {
    if (req.method === 'HEAD' && (req.url === '/alparts' || req.url === '/alparts/')) {
      res.statusCode = bucketPresent ? 200 : 404;
      res.end();
      return;
    }
    if (req.method === 'PUT') {
      const body = Buffer.concat(chunks);
      uploads.push({ headers: req.headers, body });
      res.setHeader('ETag', `"${etagOverride ?? createHash('md5').update(body).digest('hex')}"`);
      res.end();
      return;
    }
    if (req.method === 'GET' && req.url?.includes('list-type=2')) {
      const prefix = new URL(req.url, 'http://store').searchParams.get('prefix') ?? '';
      listingRequests.set(prefix, (listingRequests.get(prefix) ?? 0) + 1);
      res.setHeader('Content-Type', 'application/xml');
      if (prefix === 'attachments/v1/huge/') {
        // A valid page padded to five MiB: only its size is wrong.
        res.write(listingPage('', null).replace('</ListBucketResult>', ''));
        for (let written = 0; written < 5 * 1024 * 1024; written += 64 * 1024) res.write(' '.repeat(64 * 1024));
        res.end('</ListBucketResult>');
        return;
      }
      if (prefix === 'attachments/v1/loop/') {
        res.end(listingPage('', 'same-token'));
        return;
      }
      if (prefix === 'attachments/v1/pages/') {
        pageToken += 1;
        res.end(listingPage('', `token-${pageToken}`));
        return;
      }
      return; // never answer
    }
    if (req.method === 'GET' && req.url?.includes('/sized/')) {
      // /sized/long answers with more bytes than were stored; /sized/chunked
      // gives no length at all.
      if (req.url.includes('/sized/chunked')) {
        res.write(Buffer.alloc(5, 1));
        res.end();
        return;
      }
      const body = Buffer.alloc(req.url.includes('/sized/long') ? 10 : 5, 1);
      res.setHeader('Content-Length', String(body.length));
      res.end(body);
      return;
    }
    if (req.method === 'GET' && req.url?.includes('/small/')) {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.end(Buffer.alloc(req.url.includes('/small/large') ? 2048 : 512, 7));
      return;
    }
    if (req.method === 'GET' && req.url?.includes('/stalled/')) {
      res.writeHead(200, { 'Content-Length': '1024', 'Content-Type': 'application/octet-stream' });
      res.write(Buffer.alloc(16));
      return; // never finish
    }
    res.statusCode = 404;
    res.end();
  });
});

let storage: typeof import('./object-storage.js');

before(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
  process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
  process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
  process.env.S3_ENDPOINT = '127.0.0.1';
  process.env.S3_PORT = String((server.address() as AddressInfo).port);
  process.env.S3_ACCESS_KEY = 'test-access-key';
  process.env.S3_SECRET_KEY = 'test-secret-key';
  process.env.S3_REQUEST_TIMEOUT_MS = '1000';
  // Ambient SDK endpoint switches must not redirect the configured endpoint.
  process.env.AWS_USE_FIPS_ENDPOINT = 'true';
  process.env.AWS_USE_DUALSTACK_ENDPOINT = 'true';
  process.env.AUDIT_HEAD_OBJECT_KEY = 'test-audit-head';
  storage = await import('./object-storage.js');
});

after(() => {
  server.closeAllConnections();
  server.close();
});

describe('object storage writes and listings', () => {
  it('sends the body digest so the store rejects bytes damaged on the way', async () => {
    const body = Buffer.from('encrypted chunk bytes');
    await storage.putStoredObject('attachments/v1/test/000000', body);
    const upload = uploads.at(-1)!;
    assert.deepEqual(upload.body, body);
    assert.equal(upload.headers['content-md5'], createHash('md5').update(body).digest('base64'));
  });

  it('refuses an upload whose returned digest does not match the bytes sent', async () => {
    etagOverride = '0'.repeat(32);
    try {
      await assert.rejects(
        storage.putStoredObject('attachments/v1/test/000001', Buffer.from('other bytes')),
        /OBJECT_STORAGE_INTEGRITY/,
      );
    } finally {
      etagOverride = null;
    }
  });

  it('keeps audit head writes moving while downloads hold every storage slot', async () => {
    const downloads = await Promise.all(Array.from(
      { length: storage.MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS },
      (_, index) => storage.getStoredObject(`stalled/${index}`, 1024),
    ));
    try {
      assert.equal(storage.objectStorageWorkSnapshot().active, storage.MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS);
      await storage.writeStoredAuditHead('{"sequence":1}');
      assert.equal(uploads.at(-1)!.body.toString(), '{"sequence":1}');
      // The write finished while every download still held its slot.
      assert.equal(storage.objectStorageWorkSnapshot().active, storage.MAX_CONCURRENT_OBJECT_STORAGE_OPERATIONS);
    } finally {
      for (const download of downloads) download.destroy();
    }
  });

  it('reads a small object whole and frees its storage slot before returning', async () => {
    const bytes = await storage.readStoredObject('small/avatar', 1024);
    assert.deepEqual(bytes, Buffer.alloc(512, 7));
    assert.equal(storage.objectStorageWorkSnapshot().active, 0);
    await assert.rejects(storage.readStoredObject('small/large', 1024), /OBJECT_STORAGE_INVALID_RESPONSE/);
    assert.equal(storage.objectStorageWorkSnapshot().active, 0);
  });

  it('refuses a download whose length differs from the stored size', async () => {
    const exact = await storage.getStoredObject('sized/exact', 5);
    const chunks: Buffer[] = [];
    for await (const chunk of exact) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).length, 5);
    await assert.rejects(storage.getStoredObject('sized/long', 5), /OBJECT_STORAGE_INTEGRITY/);
    await assert.rejects(storage.getStoredObject('sized/chunked', 5), /OBJECT_STORAGE_INTEGRITY/);
    assert.equal(storage.objectStorageWorkSnapshot().active, 0, 'a refused download frees its slot');
  });

  it('never forwards a byte past the expected length', async () => {
    // Chunks arrive apart, so each is read before the next one is checked.
    async function* trickle() {
      yield Buffer.alloc(3, 1);
      await new Promise((resolve) => setTimeout(resolve, 10));
      yield Buffer.alloc(3, 2);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const forwarded: Buffer[] = [];
    const limited = storage.exactLengthStream(Readable.from(trickle()), 5);
    await assert.rejects(async () => {
      for await (const chunk of limited) forwarded.push(chunk);
    }, /OBJECT_STORAGE_INTEGRITY/);
    assert.ok(Buffer.concat(forwarded).length <= 5);
    const short = storage.exactLengthStream(Readable.from([Buffer.alloc(3, 1)]), 5);
    await assert.rejects(async () => {
      for await (const _chunk of short) { /* drain */ }
    }, /OBJECT_STORAGE_INTEGRITY/);
  });

  it('refuses a listing page larger than any real page', async () => {
    await assert.rejects(storage.reconcileStoredUpload('attachments/v1/huge', new Set()), /OBJECT_STORAGE_LIST_LIMIT/);
  });

  it('stops a listing that repeats its token or never ends', async () => {
    await storage.reconcileStoredUpload('attachments/v1/loop', new Set());
    assert.ok(listingRequests.get('attachments/v1/loop/')! <= 2);
    await assert.rejects(storage.reconcileStoredUpload('attachments/v1/pages', new Set()), /OBJECT_STORAGE_LIST_LIMIT/);
    assert.ok(listingRequests.get('attachments/v1/pages/')! <= 4);
  });

  it('fails readiness once the bucket is gone, not only at startup', async () => {
    await storage.checkObjectStorage();
    bucketPresent = false;
    try {
      await assert.rejects(storage.checkObjectStorage(), /OBJECT_STORAGE_BUCKET_MISSING/);
    } finally {
      bucketPresent = true;
    }
    await storage.checkObjectStorage();
  });

  it('reports a listing that outlives its deadline as a storage timeout', async () => {
    await assert.rejects(
      storage.reconcileStoredUpload('attachments/v1/test', new Set()),
      (error: Error) => storage.isObjectStorageTimeout(error),
    );
  });
});
