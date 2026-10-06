import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

// A minimal S3 endpoint: it records uploads, can answer with a chosen ETag,
// never answers listings so their deadline can be observed, and starts but
// never finishes downloads under stalled/ so they hold their storage slots.
const uploads: Array<{ headers: IncomingMessage['headers']; body: Buffer }> = [];
let etagOverride: string | null = null;
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const chunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => chunks.push(chunk));
  req.on('end', () => {
    if (req.method === 'PUT') {
      const body = Buffer.concat(chunks);
      uploads.push({ headers: req.headers, body });
      res.setHeader('ETag', `"${etagOverride ?? createHash('md5').update(body).digest('hex')}"`);
      res.end();
      return;
    }
    if (req.method === 'GET' && req.url?.includes('list-type=2')) return; // never answer
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
      (_, index) => storage.getStoredObject(`stalled/${index}`),
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

  it('reports a listing that outlives its deadline as a storage timeout', async () => {
    await assert.rejects(
      storage.reconcileStoredUpload('attachments/v1/test', new Set()),
      (error: Error) => storage.isObjectStorageTimeout(error),
    );
  });
});
