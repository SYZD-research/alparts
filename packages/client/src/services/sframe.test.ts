import { describe, expect, it } from 'vitest';
import headerVectors from './sframe-header-vectors.json';
import {
  SFrameReplayWindow,
  decodeSFrameHeader,
  deriveSFrameKey,
  deriveSFrameKeyMaterial,
  encodeSFrameHeader,
  sframeDecrypt,
  sframeEncrypt,
  sframeHeader,
} from './sframe';

const hex = (value: string) => Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const toHex = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

// RFC 9605 Appendix C.3, cipher suite 0x0004 (AES_128_GCM_SHA256_128).
const VECTOR = {
  kid: 0x123n,
  ctr: 0x4567n,
  baseKey: hex('000102030405060708090a0b0c0d0e0f'),
  key: 'd34f547f4ca4f9a7447006fe7fcbf768',
  salt: '75234edefe07819026751816',
  metadata: hex('4945544620534672616d65205747'),
  plaintext: hex('64726166742d696574662d736672616d652d656e63'),
  ciphertext: '9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb',
};

describe('SFrame headers (RFC 9605 Appendix C.1)', () => {
  it('encodes and decodes every header test vector', () => {
    expect(headerVectors.vectors).toHaveLength(289);
    for (const [kid, ctr, header] of headerVectors.vectors) {
      expect(toHex(encodeSFrameHeader(BigInt(kid!), BigInt(ctr!)))).toBe(header);
      expect(decodeSFrameHeader(hex(header!))).toEqual({ kid: BigInt(kid!), ctr: BigInt(ctr!), length: header!.length / 2 });
    }
  });

  it('refuses truncated and non-minimal headers', () => {
    expect(decodeSFrameHeader(new Uint8Array(0))).toBeNull();
    expect(decodeSFrameHeader(hex('99012345'))).toBeNull();      // CTR cut short
    expect(decodeSFrameHeader(hex('8807'))).toBeNull();          // KID 7 must live in the config byte
    expect(decodeSFrameHeader(hex('090001'))).toBeNull();        // CTR 1 in two bytes
    expect(() => encodeSFrameHeader(-1n, 0n)).toThrow(RangeError);
    expect(() => encodeSFrameHeader(0n, 1n << 64n)).toThrow(RangeError);
  });
});

describe('SFrame encryption (RFC 9605 Appendix C.3, AES_128_GCM_SHA256_128)', () => {
  it('derives the key and salt of the test vector', async () => {
    const material = await deriveSFrameKeyMaterial(VECTOR.baseKey, VECTOR.kid);
    expect(toHex(material.key)).toBe(VECTOR.key);
    expect(toHex(material.salt)).toBe(VECTOR.salt);
  });

  it('encrypts to the test vector and decrypts it back', async () => {
    const key = await deriveSFrameKey(VECTOR.baseKey, VECTOR.kid);
    expect(key.key.extractable).toBe(false);
    const ciphertext = await sframeEncrypt(key, VECTOR.ctr, VECTOR.plaintext, VECTOR.metadata);
    expect(toHex(ciphertext)).toBe(VECTOR.ciphertext);
    expect(await sframeDecrypt(key, hex(VECTOR.ciphertext), VECTOR.metadata)).toEqual(VECTOR.plaintext);
  });

  it('rejects any change to the frame, the metadata or the key', async () => {
    const key = await deriveSFrameKey(VECTOR.baseKey, VECTOR.kid);
    const frame = hex(VECTOR.ciphertext);
    for (let index = 0; index < frame.length; index += 1) {
      const tampered = frame.slice();
      tampered[index]! ^= 0x01;
      expect(await sframeDecrypt(key, tampered, VECTOR.metadata)).toBeNull();
    }
    expect(await sframeDecrypt(key, frame, new Uint8Array(0))).toBeNull();
    expect(await sframeDecrypt(key, frame.subarray(0, frame.length - 1), VECTOR.metadata)).toBeNull();
    const other = await deriveSFrameKey(hex('0f0e0d0c0b0a09080706050403020100'), VECTOR.kid);
    expect(await sframeDecrypt(other, frame, VECTOR.metadata)).toBeNull();
    // A frame shorter than a header and a tag is not parsed at all.
    expect(sframeHeader(hex('9901234567'))).toBeNull();
  });

  it('gives each counter its own nonce', async () => {
    const key = await deriveSFrameKey(VECTOR.baseKey, 9n);
    const plaintext = new Uint8Array(32);
    const first = await sframeEncrypt(key, 0n, plaintext);
    const second = await sframeEncrypt(key, 1n, plaintext);
    expect(toHex(first.subarray(1))).not.toBe(toHex(second.subarray(1)));
    expect(await sframeDecrypt(key, first)).toEqual(plaintext);
    expect(await sframeDecrypt(key, second)).toEqual(plaintext);
  });
});

describe('SFrame replay window', () => {
  it('accepts each counter once, in any order within the window', () => {
    const window = new SFrameReplayWindow();
    for (const ctr of [5n, 3n, 4n, 9n, 6n]) {
      expect(window.isFresh(ctr)).toBe(true);
      window.accept(ctr);
      expect(window.isFresh(ctr)).toBe(false);
    }
    expect(window.isFresh(7n)).toBe(true);
    expect(window.isFresh(8n)).toBe(true);
    window.accept(200n);
    // Older than the window: refused even if never seen.
    expect(window.isFresh(7n)).toBe(false);
    expect(window.isFresh(73n)).toBe(true);
    expect(window.isFresh(72n)).toBe(false);
    expect(window.isFresh(201n)).toBe(true);
  });

  it('records nothing for a counter that was only checked', () => {
    const window = new SFrameReplayWindow();
    expect(window.isFresh(0n)).toBe(true);
    expect(window.isFresh(0n)).toBe(true);
    window.accept(0n);
    expect(window.isFresh(0n)).toBe(false);
  });
});
