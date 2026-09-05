import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('../../packages/client/public/android-bridge.js', import.meta.url), 'utf8');
function createBridge() {
  const requests = [];
  let written = 0;
  const native = {
    onmessage: (_event) => {},
    postMessage(data) {
      const message = JSON.parse(data);
      requests.push(message);
      if (message.method === 'writeSave') written += Buffer.from(message.args.chunk, 'base64').length;
      queueMicrotask(() => native.onmessage({ data: JSON.stringify({ id: message.id, result: message.method === 'writeSave' ? written : true, error: null }) }));
    },
  };
  const window = { alpartsNative: native };
  runInNewContext(source, { window, setTimeout, clearTimeout, Uint8Array, btoa: (value) => Buffer.from(value, 'binary').toString('base64') });
  return { bridge: window.alpartsDesktop, window, requests };
}
test('does not expose native capabilities in the ordinary Web client', () => {
  const window = {};
  runInNewContext(source, { window });
  assert.equal(Object.hasOwn(window, 'alpartsDesktop'), false);
});
test('publishes an immutable bridge and splits a full attachment chunk into bounded sequential writes', async () => {
  const { bridge, window, requests } = createBridge();
  assert.equal(Object.getOwnPropertyDescriptor(window, 'alpartsDesktop')?.writable, false);
  const chunk = new Uint8Array(5 * 1024 * 1024);
  chunk.fill(173);
  assert.equal(await bridge.files.writeSave('opaque-token', chunk.buffer), chunk.length);
  assert.equal(requests.length, 10);
  assert.ok(requests.every((request) => request.method === 'writeSave' && request.args.token === 'opaque-token'));
  const decoded = Buffer.concat(requests.map((request) => Buffer.from(request.args.chunk, 'base64')));
  assert.ok(decoded.equals(Buffer.from(chunk)));
});
