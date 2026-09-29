import { crc32, inflateSync } from 'node:zlib';
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
    .refine((text) => !UNSAFE_BIO_TEXT.test(text), '自己紹介に使用できない文字が含まれています。')
    .transform((text) => text.normalize('NFC').split('\n').map((line) => line.trimEnd()).join('\n').trim())
    .refine((text) => [...text].length <= MAX_BIO_CHARACTERS, `自己紹介は${MAX_BIO_CHARACTERS}文字以内にしてください。`)
    .refine((text) => text.split('\n').length <= MAX_BIO_LINES, `自己紹介は${MAX_BIO_LINES}行以内にしてください。`)
    .refine((text) => text.length === 0 || /[\p{L}\p{N}\p{P}\p{S}]/u.test(text), '自己紹介に表示できる文字を含めてください。');
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * Accepts only a 256x256, 8-bit RGB/RGBA, non-interlaced PNG whose chunks and
 * compressed pixel data are well formed, and returns it rebuilt from IHDR,
 * IDAT and IEND alone (text, colour-profile and every other ancillary chunk
 * is dropped). Clients re-encode through a canvas before upload; this is the
 * server-side check that nothing else is stored or served.
 */
export function sanitizeAvatarPng(input: Buffer): Buffer {
  if (input.length > MAX_AVATAR_BYTES || input.length < PNG_SIGNATURE.length || !input.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('INVALID_AVATAR');
  }
  const kept: Buffer[] = [];
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
    const chunk = input.subarray(offset, end);
    if (type === 'IHDR') {
      if (header || length !== 13) throw new Error('INVALID_AVATAR');
      header = data;
      kept.push(chunk);
    } else if (!header) {
      throw new Error('INVALID_AVATAR');
    } else if (type === 'IDAT') {
      if (idatDone) throw new Error('INVALID_AVATAR');
      idat.push(data);
      kept.push(chunk);
    } else if (type === 'IEND') {
      if (length !== 0 || idat.length === 0) throw new Error('INVALID_AVATAR');
      ended = true;
      kept.push(chunk);
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
  const expected = height * (1 + width * (colorType === 6 ? 4 : 3));
  let pixels: Buffer;
  try {
    pixels = inflateSync(Buffer.concat(idat), { maxOutputLength: expected + 1 });
  } catch {
    throw new Error('INVALID_AVATAR');
  }
  if (pixels.length !== expected) throw new Error('INVALID_AVATAR');
  for (let row = 0; row < height; row += 1) {
    if (pixels[row * (expected / height)] > 4) throw new Error('INVALID_AVATAR');
  }
  return Buffer.concat([PNG_SIGNATURE, ...kept]);
}
