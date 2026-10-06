import { crc32, deflateSync, inflateSync } from 'node:zlib';
import { z } from 'zod';

export const MAX_BIO_CHARACTERS = 200;
export const MAX_BIO_LINES = 5;
export const AVATAR_SIZE = 256;
export const MAX_AVATAR_BYTES = 320 * 1024;  // worst case: incompressible 256x256 RGBA

// Same controls as display names, except that plain line breaks are allowed.
const UNSAFE_BIO_TEXT = /(?!\n)[\p{Cc}\p{Cf}\p{Zl}\p{Zp}͏ᅟᅠ឴឵⠀ㅤﾠ]/u;

/** Plain-text self-introduction: at most 200 characters and 5 lines. Empty clears it. */
export function profileBio() {
  return z.string()
    .max(MAX_BIO_CHARACTERS * 4)
    .refine((text) => !UNSAFE_BIO_TEXT.test(text), 'The bio contains characters that cannot be used.')
    .transform((text) => text.normalize('NFC').split('\n').map((line) => line.trimEnd()).join('\n').trim())
    .refine((text) => [...text].length <= MAX_BIO_CHARACTERS, `The bio must be ${MAX_BIO_CHARACTERS} characters or fewer.`)
    .refine((text) => text.split('\n').length <= MAX_BIO_LINES, `The bio must be ${MAX_BIO_LINES} lines or fewer.`)
    .refine((text) => text.length === 0 || /[\p{L}\p{N}\p{P}\p{S}]/u.test(text), 'The bio must contain visible characters.');
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * Accepts only a 256x256, 8-bit RGB/RGBA, non-interlaced PNG whose chunks and
 * compressed pixel data are well formed, and returns a new PNG encoded from
 * the decoded pixels alone: IHDR, one freshly compressed IDAT and IEND.
 * Nothing else from the upload survives (no ancillary chunks and no bytes
 * hidden after the compressed stream), and equal pixels give equal bytes.
 * Clients re-encode through a canvas before upload; this is the server-side
 * guarantee for what is stored and served.
 */
export function sanitizeAvatarPng(input: Buffer): Buffer {
  if (input.length > MAX_AVATAR_BYTES || input.length < PNG_SIGNATURE.length || !input.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('INVALID_AVATAR');
  }
  const idat: Buffer[] = [];
  let offset = 8;
  let header: Buffer | null = null;
  let ended = false;
  let idatDone = false;
  while (offset < input.length) {
    if (ended || offset + 12 > input.length) throw new Error('INVALID_AVATAR');
    const length = input.readUInt32BE(offset);
    const type = input.toString('latin1', offset + 4, offset + 8);
    const end = offset + 12 + length;
    if (!/^[A-Za-z]{4}$/.test(type) || length > MAX_AVATAR_BYTES || end > input.length) throw new Error('INVALID_AVATAR');
    const data = input.subarray(offset + 8, offset + 8 + length);
    if (crc32(data, crc32(input.subarray(offset + 4, offset + 8))) !== input.readUInt32BE(offset + 8 + length)) {
      throw new Error('INVALID_AVATAR');
    }
    if (type === 'IHDR') {
      if (header || length !== 13) throw new Error('INVALID_AVATAR');
      header = data;
    } else if (!header) {
      throw new Error('INVALID_AVATAR');
    } else if (type === 'IDAT') {
      if (idatDone) throw new Error('INVALID_AVATAR');
      idat.push(data);
    } else if (type === 'IEND') {
      if (length !== 0 || idat.length === 0) throw new Error('INVALID_AVATAR');
      ended = true;
    } else if (type.charCodeAt(0) < 0x61) {
      throw new Error('INVALID_AVATAR');          // unknown critical chunk (e.g. PLTE is not expected)
    } else if (idat.length > 0) {
      idatDone = true;                             // IDAT chunks must be consecutive
    }
    offset = end;
  }
  if (!header || !ended) throw new Error('INVALID_AVATAR');
  const width = header.readUInt32BE(0);
  const height = header.readUInt32BE(4);
  const [bitDepth, colorType, compression, filter, interlace] = header.subarray(8, 13);
  if (width !== AVATAR_SIZE || height !== AVATAR_SIZE || bitDepth !== 8 || ![2, 6].includes(colorType)
    || compression !== 0 || filter !== 0 || interlace !== 0) {
    throw new Error('INVALID_AVATAR');
  }
  // The decompressed image must be exactly rows of (filter byte + pixels).
  const channels = colorType === 6 ? 4 : 3;
  const stride = 1 + width * channels;
  const expected = height * stride;
  let pixels: Buffer;
  try {
    pixels = inflateSync(Buffer.concat(idat), { maxOutputLength: expected + 1 });
  } catch {
    throw new Error('INVALID_AVATAR');
  }
  if (pixels.length !== expected) throw new Error('INVALID_AVATAR');
  // Undo every PNG predictor before re-encoding. Recompressing the filtered
  // scanlines would keep encoding differences in an otherwise identical image.
  const canonical = Buffer.alloc(height * (1 + width * 4));
  for (let row = 0; row < height; row += 1) {
    const start = row * stride + 1;
    const filter = pixels[start - 1];
    if (filter > 4) throw new Error('INVALID_AVATAR');
    for (let x = 0; x < width * channels; x += 1) {
      const left = x >= channels ? pixels[start + x - channels] : 0;
      const up = row > 0 ? pixels[start + x - stride] : 0;
      const upperLeft = row > 0 && x >= channels ? pixels[start + x - stride - channels] : 0;
      const predictor = filter === 0 ? 0 : filter === 1 ? left : filter === 2 ? up
        : filter === 3 ? Math.floor((left + up) / 2) : paeth(left, up, upperLeft);
      pixels[start + x] = (pixels[start + x] + predictor) & 255;
    }
    for (let x = 0; x < width; x += 1) {
      const source = start + x * channels;
      const target = row * (1 + width * 4) + 1 + x * 4;
      pixels.copy(canonical, target, source, source + 3);
      canonical[target + 3] = channels === 4 ? pixels[source + 3] : 255;
    }
  }
  const canonicalHeader = Buffer.from(header);
  canonicalHeader[9] = 6; // Normalize opaque RGB and RGBA to the same format.
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', canonicalHeader),
    pngChunk('IDAT', deflateSync(canonical, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function paeth(left: number, up: number, upperLeft: number): number {
  const prediction = left + up - upperLeft;
  const a = Math.abs(prediction - left);
  const b = Math.abs(prediction - up);
  const c = Math.abs(prediction - upperLeft);
  return a <= b && a <= c ? left : b <= c ? up : upperLeft;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(type, 4, 'latin1');
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(data, crc32(chunk.subarray(4, 8))), 8 + data.length);
  return chunk;
}
