/**
 * SFrame (RFC 9605) for call audio, with cipher suite AES_128_GCM_SHA256_128.
 *
 * Every encoded audio frame is encrypted by the sender before it leaves the
 * browser and decrypted by each receiver, so a media server forwarding the
 * frames sees only the header (key id and counter) and the ciphertext.
 */

export const SFRAME_CIPHER_SUITE = 0x0004;
const KEY_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_UINT64 = (1n << 64n) - 1n;
const encoder = new TextEncoder();

export interface SFrameKey {
  kid: bigint;
  key: CryptoKey;
  salt: Uint8Array;
}

function assertUint64(value: bigint, name: string): void {
  if (value < 0n || value > MAX_UINT64) throw new RangeError(`${name} out of range`);
}

function minimalBytes(value: bigint): Uint8Array {
  let length = 1;
  while (length < 8 && value >> BigInt(8 * length) !== 0n) length += 1;
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[length - 1 - index] = Number((value >> BigInt(8 * index)) & 0xffn);
  }
  return bytes;
}

function bigEndian(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[length - 1 - index] = Number((value >> BigInt(8 * index)) & 0xffn);
  }
  return bytes;
}

function readBigEndian(bytes: Uint8Array, offset: number, length: number): bigint {
  let value = 0n;
  for (let index = 0; index < length; index += 1) value = (value << 8n) | BigInt(bytes[offset + index]!);
  return value;
}

/** The SFrame header for a key id and counter (Section 4.3). */
export function encodeSFrameHeader(kid: bigint, ctr: bigint): Uint8Array {
  assertUint64(kid, 'kid');
  assertUint64(ctr, 'ctr');
  const kidBytes = kid < 8n ? null : minimalBytes(kid);
  const ctrBytes = ctr < 8n ? null : minimalBytes(ctr);
  const config = (kidBytes ? 0x80 | ((kidBytes.length - 1) << 4) : Number(kid) << 4)
    | (ctrBytes ? 0x08 | (ctrBytes.length - 1) : Number(ctr));
  const header = new Uint8Array(1 + (kidBytes?.length ?? 0) + (ctrBytes?.length ?? 0));
  header[0] = config;
  if (kidBytes) header.set(kidBytes, 1);
  if (ctrBytes) header.set(ctrBytes, 1 + (kidBytes?.length ?? 0));
  return header;
}

/**
 * The key id, counter and header length of an SFrame ciphertext, or null when
 * the header is truncated or not minimally encoded.
 */
export function decodeSFrameHeader(data: Uint8Array): { kid: bigint; ctr: bigint; length: number } | null {
  if (data.length < 1) return null;
  const config = data[0]!;
  const kidLength = config & 0x80 ? ((config >> 4) & 0x07) + 1 : 0;
  const ctrLength = config & 0x08 ? (config & 0x07) + 1 : 0;
  const length = 1 + kidLength + ctrLength;
  if (data.length < length) return null;
  const kid = kidLength ? readBigEndian(data, 1, kidLength) : BigInt((config >> 4) & 0x07);
  const ctr = ctrLength ? readBigEndian(data, 1 + kidLength, ctrLength) : BigInt(config & 0x07);
  // Values below 8 live in the config byte, and longer ones use the fewest
  // bytes, so every (kid, ctr) has exactly one header.
  const canonical = encodeSFrameHeader(kid, ctr);
  if (canonical.length !== length || canonical.some((byte, index) => byte !== data[index])) return null;
  return { kid, ctr, length };
}

function label(prefix: string, kid: bigint): Uint8Array {
  const text = encoder.encode(prefix);
  const out = new Uint8Array(text.length + 10);
  out.set(text, 0);
  out.set(bigEndian(kid, 8), text.length);
  out.set(bigEndian(BigInt(SFRAME_CIPHER_SUITE), 2), text.length + 8);
  return out;
}

/** sframe_key and sframe_salt for a base key (Section 4.4.2). */
export async function deriveSFrameKeyMaterial(baseKey: Uint8Array, kid: bigint): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  assertUint64(kid, 'kid');
  if (baseKey.length < 16) throw new RangeError('base key too short');
  const ikm = await crypto.subtle.importKey('raw', baseKey as Uint8Array<ArrayBuffer>, 'HKDF', false, ['deriveBits']);
  // HKDF-Extract with an empty salt, then HKDF-Expand with each label.
  const expand = async (info: Uint8Array, bytes: number) => new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: info as Uint8Array<ArrayBuffer> },
    ikm,
    bytes * 8,
  ));
  return {
    key: await expand(label('SFrame 1.0 Secret key ', kid), KEY_BYTES),
    salt: await expand(label('SFrame 1.0 Secret salt ', kid), NONCE_BYTES),
  };
}

/** The encryption key for one key id; the AES key cannot be exported. */
export async function deriveSFrameKey(baseKey: Uint8Array, kid: bigint): Promise<SFrameKey> {
  const material = await deriveSFrameKeyMaterial(baseKey, kid);
  const key = await crypto.subtle.importKey('raw', material.key as Uint8Array<ArrayBuffer>, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  material.key.fill(0);
  return { kid, key, salt: material.salt };
}

function nonceFor(salt: Uint8Array, ctr: bigint): Uint8Array<ArrayBuffer> {
  const nonce = bigEndian(ctr, NONCE_BYTES);
  for (let index = 0; index < NONCE_BYTES; index += 1) nonce[index]! ^= salt[index]!;
  return nonce as Uint8Array<ArrayBuffer>;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** header || AEAD ciphertext (Section 4.4.3). */
export async function sframeEncrypt(
  key: SFrameKey,
  ctr: bigint,
  plaintext: Uint8Array,
  metadata: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> {
  const header = encodeSFrameHeader(key.kid, ctr);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceFor(key.salt, ctr), additionalData: concat(header, metadata), tagLength: TAG_BYTES * 8 },
    key.key,
    plaintext as Uint8Array<ArrayBuffer>,
  ));
  return concat(header, ciphertext);
}

/** The parsed header of an SFrame ciphertext, before choosing a key. */
export function sframeHeader(data: Uint8Array): { kid: bigint; ctr: bigint; length: number } | null {
  const header = decodeSFrameHeader(data);
  return header && data.length >= header.length + TAG_BYTES ? header : null;
}

/** The plaintext, or null when the ciphertext does not authenticate under the key (Section 4.4.4). */
export async function sframeDecrypt(
  key: SFrameKey,
  data: Uint8Array,
  metadata: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array | null> {
  const header = sframeHeader(data);
  if (!header || header.kid !== key.kid) return null;
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonceFor(key.salt, header.ctr),
        additionalData: concat(data.subarray(0, header.length), metadata),
        tagLength: TAG_BYTES * 8,
      },
      key.key,
      data.subarray(header.length) as Uint8Array<ArrayBuffer>,
    ));
  } catch {
    return null;
  }
}

/**
 * Counters already accepted for one key: the highest one and a window of the
 * 128 before it. A counter is accepted once, and only after it decrypted.
 */
export class SFrameReplayWindow {
  private static readonly SIZE = 128n;
  private highest = -1n;
  private seen = 0n;

  /** Whether a counter is new (it is not recorded until `accept`). */
  isFresh(ctr: bigint): boolean {
    if (ctr > this.highest) return true;
    const age = this.highest - ctr;
    return age < SFrameReplayWindow.SIZE && (this.seen & (1n << age)) === 0n;
  }

  accept(ctr: bigint): void {
    if (!this.isFresh(ctr)) return;
    if (ctr > this.highest) {
      const shift = this.highest < 0n ? SFrameReplayWindow.SIZE : ctr - this.highest;
      this.seen = shift >= SFrameReplayWindow.SIZE ? 0n : (this.seen << shift) & ((1n << SFrameReplayWindow.SIZE) - 1n);
      this.highest = ctr;
      this.seen |= 1n;
      return;
    }
    this.seen |= 1n << (this.highest - ctr);
  }
}
