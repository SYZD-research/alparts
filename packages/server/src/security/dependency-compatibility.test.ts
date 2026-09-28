import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { PassThrough } from 'node:stream';
import { it } from 'node:test';

it('MinIO receives notification records through the patched modern JSON parser', async () => {
  const require = createRequire(import.meta.url);
  const minioRequire = createRequire(require.resolve('minio'));
  const { NotificationPoller } = minioRequire('./notification.js');
  const response = new PassThrough();
  const poller = new NotificationPoller({ region: 'us-east-1', makeRequestAsync: async () => response }, 'test', '', '', []);
  const record = { eventName: 's3:ObjectCreated:Put', s3: { object: { key: 'test-object' } } };
  const received = new Promise((resolve, reject) => {
    poller.once('notification', (value: unknown) => { poller.stop(); resolve(value); });
    poller.once('error', reject);
  });
  poller.start();
  response.end(JSON.stringify({ Records: [record] }) + '\n');
  assert.deepEqual(await received, record);
});

it('query-string uses the updated URI decoder through its CommonJS bridge', () => {
  const require = createRequire(import.meta.url);
  const minioRequire = createRequire(require.resolve('minio'));
  const query = minioRequire('query-string');
  assert.equal(query.parse('name=%E6%97%A5%E6%9C%AC%E8%AA%9E').name, '日本語');
  assert.doesNotThrow(() => query.parse('name=%E0%A4%A'));
});
