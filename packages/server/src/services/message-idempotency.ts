/** Message idempotency keys are stored per author as `${authorId}:${key}`. */
export function scopedIdempotencyKey(userId: string, key: string): string {
  return `${userId}:${key}`;
}

/** The key the author signed, as clients see it. */
export function signedIdempotencyKey(message: { authorId: string; idempotencyKey: string | null }): string | null {
  const prefix = `${message.authorId}:`;
  return typeof message.idempotencyKey === 'string' && message.idempotencyKey.startsWith(prefix)
    ? message.idempotencyKey.slice(prefix.length)
    : message.idempotencyKey;
}
