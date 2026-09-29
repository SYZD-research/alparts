import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { crc32, deflateSync, inflateSync } from 'node:zlib';
import { AVATAR_SIZE, MAX_AVATAR_BYTES, profileBio, sanitizeAvatarPng } from './profile-input.js';

function chunk(type: string, data: Buffer = Buffer.alloc(0), badCrc = false): Buffer {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(data.length, 0);
  header.write(type, 4, 'latin1');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE((crc32(data, crc32(Buffer.from(type, 'latin1'))) ^ (badCrc ? 1 : 0)) >>> 0);
  return Buffer.concat([header, data, crc]);
}

function ihdr(width = AVATAR_SIZE, height = AVATAR_SIZE, colorType = 6, interlace = 0): Buffer {
  const data = Buffer.alloc(13);
  data.writeUInt32BE(width, 0);
  data.writeUInt32BE(height, 4);
  data.set([8, colorType, 0, 0, interlace], 8);
  return chunk('IHDR', data);
}

function pixels(width = AVATAR_SIZE, height = AVATAR_SIZE, channels = 4, filter = 0): Buffer {
  const rows = [];
  for (let y = 0; y < height; y += 1) rows.push(Buffer.concat([Buffer.from([filter]), Buffer.alloc(width * channels, y)]));
  return deflateSync(Buffer.concat(rows));
}

const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const png = (...chunks: Buffer[]) => Buffer.concat([signature, ...chunks]);

describe('avatar PNG sanitizer', () => {
  it('decodes all five filters and canonicalizes opaque RGB/RGBA, including edges and byte wrap', () => {
    const expected = Buffer.alloc(AVATAR_SIZE * (1 + AVATAR_SIZE * 4));
    for (let y = 0; y < AVATAR_SIZE; y++) {
      for (let x = 0; x < AVATAR_SIZE; x++) {
        expected.set([(x * 73 + y * 17) & 255, (x * 19 + y * 137) & 255,
          (x * 251 + y * 83) & 255, 255], y * 1025 + 1 + x * 4);
      }
    }
    const canonical = png(ihdr(), chunk('IDAT', deflateSync(expected, { level: 9 })), chunk('IEND'));
    for (const channels of [3, 4]) {
      for (const mode of [0, 1, 2, 3, 4, 'mixed'] as const) {
        const stride = AVATAR_SIZE * channels;
        const raw = Buffer.alloc(AVATAR_SIZE * (1 + stride));
        const sample = (x: number, y: number) => x < 0 || y < 0 ? 0
          : expected[y * 1025 + 1 + Math.floor(x / channels) * 4 + x % channels];
        for (let y = 0; y < AVATAR_SIZE; y++) {
          const filter = mode === 'mixed' ? y % 5 : mode;
          raw[y * (stride + 1)] = filter;
          for (let x = 0; x < stride; x++) {
            const a = sample(x - channels, y), b = sample(x, y - 1), c = sample(x - channels, y - 1);
            // Independent encoder: rank candidate distances with PNG's tie
            // order. The expected decoded bytes come directly from coordinates.
            const paeth = [a, b, c].map((v, order) => ({ v, order, distance: Math.abs(a + b - c - v) }))
              .sort((l, r) => l.distance - r.distance || l.order - r.order)[0].v;
            const prediction = [0, a, b, Math.floor((a + b) / 2), paeth][filter];
            raw[y * (stride + 1) + 1 + x] = (sample(x, y) - prediction) & 255;
          }
        }
        const input = png(ihdr(AVATAR_SIZE, AVATAR_SIZE, channels === 4 ? 6 : 2),
          chunk('IDAT', deflateSync(raw)), chunk('IEND'));
        assert.deepEqual(sanitizeAvatarPng(input), canonical, `${channels} channels, filter ${mode}`);
      }
    }
    assert.deepEqual(sanitizeAvatarPng(canonical), canonical);
  });

  it('keeps a valid 256x256 image and drops ancillary chunks', () => {
    const idat = pixels();
    const input = png(ihdr(), chunk('tEXt', Buffer.from('Comment\0secret location')), chunk('IDAT', idat.subarray(0, 100)),
      chunk('IDAT', idat.subarray(100)), chunk('eXIf', Buffer.from('gps')), chunk('IEND'));
    const output = sanitizeAvatarPng(input);
    assert.equal(output.includes(Buffer.from('secret location')), false);
    assert.equal(output.includes(Buffer.from('eXIf')), false);
    assert.deepEqual(sanitizeAvatarPng(output), output, 'the result is itself a valid avatar');
    assert.equal(sanitizeAvatarPng(png(ihdr(AVATAR_SIZE, AVATAR_SIZE, 2), chunk('IDAT', pixels(AVATAR_SIZE, AVATAR_SIZE, 3)), chunk('IEND'))).length > 0, true);
  });

  it('stores only re-encoded pixels, never bytes hidden after the compressed stream', () => {
    const hidden = Buffer.from('<script>alert(1)</script>'.repeat(40));
    const plain = sanitizeAvatarPng(png(ihdr(), chunk('IDAT', pixels()), chunk('IEND')));
    for (const trailer of [hidden, deflateSync(hidden)]) {
      const output = sanitizeAvatarPng(png(ihdr(), chunk('IDAT', Buffer.concat([pixels(), trailer])), chunk('IEND')));
      assert.equal(output.includes(hidden.subarray(0, 25)), false);
      assert.deepEqual(output, plain, 'equal pixels give equal bytes');
    }
    // One IDAT whose compressed stream ends exactly at the chunk end.
    const idatLength = plain.readUInt32BE(33);
    assert.equal(plain.toString('latin1', 37, 41), 'IDAT');
    const idat = plain.subarray(41, 41 + idatLength);
    const { engine } = inflateSync(idat, { info: true }) as unknown as { engine: { bytesWritten: number } };
    assert.equal(engine.bytesWritten, idat.length);
    assert.equal(plain.toString('latin1', 41 + idatLength + 8, 41 + idatLength + 12), 'IEND');
  });

  it('rejects anything that is not exactly the expected image', () => {
    const idat = chunk('IDAT', pixels());
    const cases: Array<[string, Buffer]> = [
      ['not a PNG', Buffer.from('<svg onload="alert(1)"></svg>')],
      ['wrong size', png(ihdr(512, 512), chunk('IDAT', pixels(512, 512)), chunk('IEND'))],
      ['interlaced', png(ihdr(AVATAR_SIZE, AVATAR_SIZE, 6, 1), idat, chunk('IEND'))],
      ['palette colour type', png(ihdr(AVATAR_SIZE, AVATAR_SIZE, 3), idat, chunk('IEND'))],
      ['bad CRC', png(ihdr(), chunk('IDAT', pixels(), true), chunk('IEND'))],
      ['missing IEND', png(ihdr(), idat)],
      ['data after IEND', png(ihdr(), idat, chunk('IEND'), chunk('tEXt', Buffer.from('x')))],
      ['unknown critical chunk', png(ihdr(), chunk('ABCD', Buffer.from('x')), idat, chunk('IEND'))],
      ['split IDAT', png(ihdr(), chunk('IDAT', pixels().subarray(0, 50)), chunk('tEXt'), chunk('IDAT', pixels().subarray(50)), chunk('IEND'))],
      ['short pixel data', png(ihdr(), chunk('IDAT', pixels(AVATAR_SIZE, 10)), chunk('IEND'))],
      ['invalid row filter', png(ihdr(), chunk('IDAT', pixels(AVATAR_SIZE, AVATAR_SIZE, 4, 9)), chunk('IEND'))],
      ['garbage compressed data', png(ihdr(), chunk('IDAT', Buffer.from('not zlib')), chunk('IEND'))],
      ['too large', Buffer.concat([png(ihdr(), idat), Buffer.alloc(MAX_AVATAR_BYTES)])],
    ];
    for (const [name, input] of cases) assert.throws(() => sanitizeAvatarPng(input), /INVALID_AVATAR/, name);
  });
});

describe('self-introduction text', () => {
  const bio = profileBio();
  it('accepts plain multilingual text with up to five lines', () => {
    assert.equal(bio.parse('  こんにちは\nよろしくお願いします  '), 'こんにちは\nよろしくお願いします');
    assert.equal(bio.parse(''), '');
    assert.equal(bio.parse('一\n二\n三\n四\n五'), '一\n二\n三\n四\n五');
    assert.equal(bio.parse('😀'.repeat(200)).length, 400);
  });

  it('rejects hidden, direction-changing and oversized text', () => {
    for (const value of ['a‮b', 'a​b', 'a\rb', 'a b', '⠀', 'x'.repeat(201), '😀'.repeat(201), '1\n2\n3\n4\n5\n6']) {
      assert.equal(bio.safeParse(value).success, false, JSON.stringify(value));
    }
  });
});
