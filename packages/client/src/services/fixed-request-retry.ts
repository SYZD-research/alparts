export interface FixedRequestRetryOptions {
  attempts?: number;
  baseDelayMs?: number;
  isCurrent?: () => boolean;
  staleError?: () => Error;
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
  if (!Number.isSafeInteger(attempts) || attempts < 1) throw new Error('Retry attempts must be a positive integer');
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) throw new Error('Retry delay must be non-negative');

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
        await new Promise((resolve) => setTimeout(resolve, baseDelayMs * (2 ** attempt)));
      }
    }
  }
  throw lastError;
}
