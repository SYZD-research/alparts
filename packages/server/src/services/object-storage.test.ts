import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

// A minimal S3 endpoint: it records uploads, can answer with a chosen ETag,
// and never answers listings so their deadline can be observed.
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

  it('reports a listing that outlives its deadline as a storage timeout', async () => {
    await assert.rejects(
      storage.reconcileStoredUpload('attachments/v1/test', new Set()),
      (error: Error) => storage.isObjectStorageTimeout(error),
    );
  });
});
