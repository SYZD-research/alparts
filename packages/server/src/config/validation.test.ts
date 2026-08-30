import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseBindHost, parseBoundedInteger, parseCorsOrigins, parseVoiceIceServers } from './validation.js';

describe('configuration validation', () => {
  it('binds to loopback by default and accepts only IP literals', () => {
    assert.equal(parseBindHost(undefined), '127.0.0.1');
    for (const valid of ['127.0.0.1', '0.0.0.0', '::1', '::']) {
      assert.equal(parseBindHost(valid), valid);
    }
    for (const invalid of ['localhost', 'app.example.test', '127.0.0.1:3000', '[::1]', '*']) {
      assert.throws(() => parseBindHost(invalid), /BIND_HOST must be an IPv4 or IPv6 literal/);
    }
  });

  it('accepts only a complete bounded decimal integer', () => {
    assert.equal(parseBoundedInteger('PORT', undefined, 3000, 1, 65_535), 3000);
    assert.equal(parseBoundedInteger('PORT', ' 443 ', 3000, 1, 65_535), 443);
    assert.equal(parseBoundedInteger('PORT', '00080', 3000, 1, 65_535), 80);
    for (const invalid of ['0', '-1', '+1', '1.5', '1e3', '3000junk', 'Infinity']) {
      assert.throws(() => parseBoundedInteger('PORT', invalid, 3000, 1, 65_535), /PORT must be an integer/);
    }
    assert.throws(() => parseBoundedInteger('PORT', '65536', 3000, 1, 65_535), /PORT must be an integer/);
  });

  it('returns canonical exact CORS origins and rejects ambiguous entries', () => {
    assert.deepEqual(
      parseCorsOrigins('https://app.example.test,http://localhost:5173,http://[::1]:5173', true),
      ['https://app.example.test', 'http://localhost:5173', 'http://[::1]:5173'],
    );
    for (const invalid of [
      '*',
      'https://app.example.test/',
      'https://user@app.example.test',
      'https://app.example.test/path',
      'https://app.example.test?query=1',
      'https://app.example.test#fragment',
      'ftp://app.example.test',
      'https://app.example.test,https://app.example.test',
    ]) {
      assert.throws(() => parseCorsOrigins(invalid, true));
    }
    assert.throws(() => parseCorsOrigins('http://app.example.test', true), /must use HTTPS/);
    assert.deepEqual(parseCorsOrigins('http://app.example.test', false), ['http://app.example.test']);
  });

  it('accepts bounded self-hosted ICE configuration and rejects unsafe forms', () => {
    assert.deepEqual(parseVoiceIceServers(undefined), []);
    assert.deepEqual(parseVoiceIceServers(JSON.stringify([
      { urls: ['stun:turn.example.test:3478'] },
      {
        urls: ['turn:turn.example.test:3478?transport=udp', 'turns:turn.example.test:5349?transport=tcp'],
        username: 'ephemeral-user',
        credential: 'ephemeral-secret',
      },
    ])), [
      { urls: ['stun:turn.example.test:3478'] },
      {
        urls: ['turn:turn.example.test:3478?transport=udp', 'turns:turn.example.test:5349?transport=tcp'],
        username: 'ephemeral-user',
        credential: 'ephemeral-secret',
      },
    ]);
    for (const invalid of [
      '{',
      '{}',
      JSON.stringify(Array.from({ length: 5 }, () => ({ urls: 'stun:turn.example.test' }))),
      JSON.stringify([{ urls: 'https://example.test' }]),
      JSON.stringify([{ urls: 'turn:user@turn.example.test', username: 'u', credential: 'c' }]),
      JSON.stringify([{ urls: 'turn:turn.example.test' }]),
      JSON.stringify([{ urls: 'stun:turn.example.test', credential: 'secret' }]),
      JSON.stringify([{ urls: 'stun:turn.example.test', credentialType: 'password' }]),
    ]) assert.throws(() => parseVoiceIceServers(invalid));
  });
});
