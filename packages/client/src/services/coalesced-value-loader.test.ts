import { describe, expect, it, vi } from 'vitest';
import { coalesceValueLoads, uniqueValueChunks } from './coalesced-value-loader';

describe('coalesceValueLoads', () => {
  it('loads one channel key once for a 64-event same-version batch', async () => {
    const loader = vi.fn(async (version: number) => `key-${version}`);
    const load = coalesceValueLoads(loader);

    await expect(Promise.all(Array.from({ length: 64 }, () => load(7))))
      .resolves.toEqual(Array.from({ length: 64 }, () => 'key-7'));
    expect(loader).toHaveBeenCalledTimes(1);
    expect(loader).toHaveBeenCalledWith(7);
  });

  it('keeps distinct versions separate', async () => {
    const loader = vi.fn(async (version: number) => version);
    const load = coalesceValueLoads(loader);
    await expect(Promise.all([load(1), load(2), load(1)])).resolves.toEqual([1, 2, 1]);
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('bounds 1,000 unique history versions to 16 API-sized chunks', () => {
    const chunks = uniqueValueChunks(Array.from({ length: 1_000 }, (_, index) => index + 1), 64);
    expect(chunks).toHaveLength(16);
    expect(chunks.every((chunk) => chunk.length <= 64)).toBe(true);
    expect(chunks.flat()).toHaveLength(1_000);
  });

  it('deduplicates repeated versions before chunking', () => {
    expect(uniqueValueChunks(Array.from({ length: 1_000 }, () => 7), 64)).toEqual([[7]]);
  });
});
