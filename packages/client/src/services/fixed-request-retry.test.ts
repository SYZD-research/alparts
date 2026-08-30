import { describe, expect, it, vi } from 'vitest';
import { boundedBackoffDelayMs, retryFixedRequest } from './fixed-request-retry';

describe('retryFixedRequest', () => {
  it('uses capped exponential backoff with bounded jitter', () => {
    expect(boundedBackoffDelayMs(0, 1_000, () => 0)).toBe(500);
    expect(boundedBackoffDelayMs(2, 1_000, () => 1)).toBe(4_000);
    expect(boundedBackoffDelayMs(8, 30_000, () => 1)).toBe(30_000);
    expect(() => boundedBackoffDelayMs(0, 30_001)).toThrow('outside the supported range');
  });

  it('reuses the identical signed envelope after a response-loss error', async () => {
    const request = Object.freeze({
      encryptedContent: 'ciphertext',
      contentNonce: 'nonce',
      idempotencyKey: 'fixed-idempotency-key',
      signature: 'fixed-signature',
    });
    const seen: typeof request[] = [];
    const operation = vi.fn(async (candidate: typeof request) => {
      seen.push(candidate);
      if (seen.length === 1) throw new TypeError('response lost');
      return { id: 'event-id' };
    });

    await expect(retryFixedRequest(
      request,
      operation,
      (error) => error instanceof TypeError,
      { attempts: 2, baseDelayMs: 0 },
    )).resolves.toEqual({ id: 'event-id' });

    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(request);
    expect(seen[1]).toBe(request);
    expect(seen[1]).toEqual(seen[0]);
  });

  it('does not retry a non-transient rejection', async () => {
    const request = { idempotencyKey: 'fixed' };
    const operation = vi.fn(async () => {
      throw new Error('forbidden');
    });

    await expect(retryFixedRequest(request, operation, () => false, {
      attempts: 3,
      baseDelayMs: 0,
    })).rejects.toThrow('forbidden');
    expect(operation).toHaveBeenCalledTimes(1);
  });
});
