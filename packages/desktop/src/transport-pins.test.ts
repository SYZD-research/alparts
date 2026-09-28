import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { it } from 'node:test';
import { matchesTransportPin, parseTransportPins } from './transport-pins.js';

it('accepts the configured current or backup key only for the exact host', async () => {
  const pem = await readFile(new URL('./fixtures/transport-pin.pem', import.meta.url), 'utf8');
  const pin = createHash('sha256').update(new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const other = Buffer.alloc(32, 1).toString('base64');
  for (const values of [[pin, other], [other, pin]]) {
    const pins = parseTransportPins({ version: 1, hosts: { 'chat.example.test': values } });
    assert.equal(matchesTransportPin('chat.example.test', pem, pins), true);
    assert.equal(matchesTransportPin('other.example.test', pem, pins), false);
    assert.equal(matchesTransportPin('chat.example.test', 'malformed certificate', pins), false);
  }
  const pins = parseTransportPins({ version: 1, hosts: { 'chat.example.test': [other, Buffer.alloc(32, 2).toString('base64')] } });
  assert.equal(matchesTransportPin('chat.example.test', pem, pins), false);
});

it('refuses empty release policies, missing rotation keys and unsafe host syntax', () => {
  assert.deepEqual(parseTransportPins({ version: 1, hosts: {} }, false), {});
  assert.throws(() => parseTransportPins({ version: 1, hosts: {} }));
  const pin = Buffer.alloc(32, 1).toString('base64');
  for (const hosts of [{ 'chat.example.test': [pin] }, { 'chat.example.test': [pin, pin] },
    { '*.example.test': [pin, Buffer.alloc(32, 2).toString('base64')] }]) {
    assert.throws(() => parseTransportPins({ version: 1, hosts }));
  }
});
