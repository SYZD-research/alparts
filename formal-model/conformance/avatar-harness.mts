// Runs the real avatar sanitizer over a corpus of well-formed and hostile PNGs.
// Output: JSON array of { name, expect, verdict, trailing, extraChunks, ms }.
import { crc32, deflateSync, inflateSync } from 'node:zlib';

const { sanitizeAvatarPng } = await import('../../packages/server/src/security/profile-input.ts');

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const chunk = (type: string, data: Buffer, badCrc = false) => {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'latin1');
  data.copy(out, 8);
  out.writeUInt32BE((crc32(data, crc32(Buffer.from(type, 'latin1'))) ^ (badCrc ? 1 : 0)) >>> 0, 8 + data.length);
  return out;
};
const ihdr = (size = 256, depth = 8, color = 6, interlace = 0) => {
  const b = Buffer.alloc(13);
  b.writeUInt32BE(size, 0); b.writeUInt32BE(size, 4); b[8] = depth; b[9] = color; b[12] = interlace;
  return b;
};
const pixels = (channels: number, filter = 0, extra = 0) => {
  const row = 1 + 256 * channels;
  const raw = Buffer.alloc(256 * row + extra);
  for (let y = 0; y < 256; y += 1) {
    raw[y * row] = filter;
    for (let x = 1; x < row; x += 1) raw[y * row + x] = (x * 7 + y * 13) & 0xff;
  }
  return raw;
};
const png = (...chunks: Buffer[]) => Buffer.concat([SIG, ...chunks]);
const END = chunk('IEND', Buffer.alloc(0));
const rgba = deflateSync(pixels(4));
const payload = Buffer.from('<script>alert(1)</script>'.repeat(400));

const corpus: Array<[string, 'accept' | 'reject' | 'observe', Buffer]> = [
  ['valid-rgba', 'accept', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba), END)],
  ['valid-rgb', 'accept', png(chunk('IHDR', ihdr(256, 8, 2)), chunk('IDAT', deflateSync(pixels(3))), END)],
  ['valid-split-idat', 'accept', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba.subarray(0, 100)), chunk('IDAT', rgba.subarray(100)), END)],
  ['ancillary-text-dropped', 'accept', png(chunk('IHDR', ihdr()), chunk('tEXt', payload), chunk('IDAT', rgba), END)],
  ['trailing-after-zlib', 'observe', png(chunk('IHDR', ihdr()), chunk('IDAT', Buffer.concat([rgba, payload])), END)],
  ['second-zlib-stream', 'observe', png(chunk('IHDR', ihdr()), chunk('IDAT', Buffer.concat([rgba, deflateSync(payload)])), END)],
  ['chunk-after-iend', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba), END, chunk('tEXt', payload))],
  ['bytes-after-iend', 'reject', Buffer.concat([png(chunk('IHDR', ihdr()), chunk('IDAT', rgba), END), payload])],
  ['ancillary-between-idat', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba.subarray(0, 100)), chunk('tEXt', payload), chunk('IDAT', rgba.subarray(100)), END)],
  ['wrong-size', 'reject', png(chunk('IHDR', ihdr(255)), chunk('IDAT', rgba), END)],
  ['16-bit', 'reject', png(chunk('IHDR', ihdr(256, 16)), chunk('IDAT', rgba), END)],
  ['palette', 'reject', png(chunk('IHDR', ihdr(256, 8, 3)), chunk('PLTE', Buffer.alloc(3)), chunk('IDAT', rgba), END)],
  ['plte-in-truecolor', 'reject', png(chunk('IHDR', ihdr()), chunk('PLTE', Buffer.alloc(3)), chunk('IDAT', rgba), END)],
  ['interlaced', 'reject', png(chunk('IHDR', ihdr(256, 8, 6, 1)), chunk('IDAT', rgba), END)],
  ['bad-crc', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba, true), END)],
  ['filter-5', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', deflateSync(pixels(4, 5))), END)],
  ['short-pixels', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', deflateSync(pixels(4).subarray(0, 1000))), END)],
  ['extra-pixels', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', deflateSync(pixels(4, 0, 1))), END)],
  ['truncated-zlib', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba.subarray(0, rgba.length - 10)), END)],
  ['no-idat', 'reject', png(chunk('IHDR', ihdr()), END)],
  ['no-signature', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', rgba), END).subarray(8)],
  ['bomb-200MB', 'reject', png(chunk('IHDR', ihdr()), chunk('IDAT', deflateSync(Buffer.alloc(200 * 1024 * 1024), { level: 9 })), END)],
];

const results = corpus.map(([name, expect, input]) => {
  const started = performance.now();
  let verdict = 'reject';
  let trailing = 0;
  let extraChunks = false;
  try {
    const out = sanitizeAvatarPng(input);
    verdict = 'accept';
    const idat: Buffer[] = [];
    for (let offset = 8; offset < out.length;) {
      const length = out.readUInt32BE(offset);
      const type = out.toString('latin1', offset + 4, offset + 8);
      if (type === 'IDAT') idat.push(out.subarray(offset + 8, offset + 8 + length));
      else if (type !== 'IHDR' && type !== 'IEND') extraChunks = true;
      offset += 12 + length;
    }
    const stream = Buffer.concat(idat);
    const { engine } = inflateSync(stream, { info: true }) as unknown as { engine: { bytesWritten: number } };
    trailing = stream.length - engine.bytesWritten;
  } catch {
    verdict = 'reject';
  }
  return { name, expect, verdict, trailing, extraChunks, ms: performance.now() - started, bytes: input.length };
});
process.stdout.write(JSON.stringify(results));
