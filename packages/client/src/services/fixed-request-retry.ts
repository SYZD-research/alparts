export interface FixedRequestRetryOptions {
  attempts?: number;
  baseDelayMs?: number;
  isCurrent?: () => boolean;
  staleError?: () => Error;
}

export const MAX_RETRY_ATTEMPTS = 8;
export const MAX_RETRY_DELAY_MS = 30_000;

export function boundedBackoffDelayMs(
  attempt: number,
  baseDelayMs: number,
  random = Math.random,
): number {
  if (!Number.isSafeInteger(attempt) || attempt < 0) throw new Error('Retry attempt must be a non-negative integer');
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0 || baseDelayMs > MAX_RETRY_DELAY_MS) {
    throw new Error('Retry delay is outside the supported range');
  }
  if (baseDelayMs === 0) return 0;
  const exponential = Math.min(MAX_RETRY_DELAY_MS, baseDelayMs * (2 ** Math.min(attempt, MAX_RETRY_ATTEMPTS)));
  const sample = Math.min(1, Math.max(0, random()));
  return Math.max(1, Math.floor(exponential * (0.5 + sample * 0.5)));
}

/**
 * Retries a request without rebuilding its authenticated payload.
 *
 * The exact same object is passed to every attempt. This matters for signed,
 * idempotent operations: a response may be lost after the server commits, and
 * rebuilding ciphertext or a signature under the same idempotency key would
 * describe a different event.
 */
export async function retryFixedRequest<TRequest, TResponse>(
  request: TRequest,
  operation: (fixedRequest: TRequest) => Promise<TResponse>,
  isTransientError: (error: unknown) => boolean,
  options: FixedRequestRetryOptions = {},
): Promise<TResponse> {
  const attempts = options.attempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 250;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > MAX_RETRY_ATTEMPTS) {
    throw new Error('Retry attempts are outside the supported range');
  }
  boundedBackoffDelayMs(0, baseDelayMs);

  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (options.isCurrent && !options.isCurrent()) {
      throw options.staleError?.() ?? new Error('Request context changed');
    }
    try {
      return await operation(request);
    } catch (error) {
      lastError = error;
      if (!isTransientError(error) || attempt === attempts - 1) throw error;
      if (options.isCurrent && !options.isCurrent()) {
        throw options.staleError?.() ?? new Error('Request context changed');
      }
      if (baseDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, boundedBackoffDelayMs(attempt, baseDelayMs)));
      }
    }
  }
  throw lastError;
}
