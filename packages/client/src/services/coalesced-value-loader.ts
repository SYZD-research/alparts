/** Concurrent callers share one in-flight load per key; settled entries expire. */
export function coalesceValueLoads<K, V>(loader: (key: K) => Promise<V>): (key: K) => Promise<V> {
  const pending = new Map<K, Promise<V>>();
  return (key: K) => {
    const existing = pending.get(key);
    if (existing) return existing;
    const started = Promise.resolve().then(() => loader(key)).finally(() => {
      if (pending.get(key) === started) pending.delete(key);
    });
    pending.set(key, started);
    return started;
  };
}

export function uniqueValueChunks<T>(values: readonly T[], chunkSize: number): T[][] {
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1) throw new Error('INVALID_CHUNK_SIZE');
  const unique = [...new Set(values)];
  const chunks: T[][] = [];
  for (let offset = 0; offset < unique.length; offset += chunkSize) {
    chunks.push(unique.slice(offset, offset + chunkSize));
  }
  return chunks;
}
