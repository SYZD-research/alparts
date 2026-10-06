import { useEffect, useState } from 'react';
import { api, ApiError } from '../services/api';

// Avatar URLs change with every new image, so a fetched image never goes stale.
const MAX_CACHED_AVATARS = 200;
// The server sends each account only a few avatars at a time; the rest wait
// here instead of being refused, and a busy answer is retried.
export const MAX_CONCURRENT_AVATAR_FETCHES = 4;
const AVATAR_FETCH_ATTEMPTS = 3;
const cache = new Map<string, Promise<string | null>>();
const resolved = new Map<string, string>();
let generation = 0;
let activeFetches = 0;
const waiting: Array<{ start: () => void; cancel: () => void }> = [];

class AvatarCacheCleared extends Error {}

async function withFetchSlot<T>(operation: () => Promise<T>): Promise<T> {
  if (activeFetches < MAX_CONCURRENT_AVATAR_FETCHES) {
    activeFetches += 1;
  } else {
    // A released slot passes straight to the next waiter.
    await new Promise<void>((start, cancel) => waiting.push({ start, cancel: () => cancel(new AvatarCacheCleared()) }));
  }
  try {
    return await operation();
  } finally {
    const next = waiting.shift();
    if (next) next.start();
    else activeFetches -= 1;
  }
}

function isBusy(error: unknown): error is ApiError {
  return error instanceof ApiError && (error.status === 429 || error.status === 503);
}

async function fetchAvatar(avatarUrl: string, fetchGeneration: number): Promise<ArrayBuffer> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await withFetchSlot(() => {
        if (fetchGeneration !== generation) throw new AvatarCacheCleared();
        return api.getAvatarBytes(avatarUrl);
      });
    } catch (error) {
      if (attempt >= AVATAR_FETCH_ATTEMPTS || !isBusy(error)) throw error;
      const delayMs = Math.min(5_000, (error.retryAfterSeconds ?? 0) * 1000 || 300 * 2 ** (attempt - 1));
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

export function loadAvatar(avatarUrl: string): Promise<string | null> {
  const existing = cache.get(avatarUrl);
  if (existing) return existing;
  const fetchGeneration = generation;
  const pending = fetchAvatar(avatarUrl, fetchGeneration)
    .then((bytes) => {
      if (fetchGeneration !== generation) return null;
      const objectUrl = URL.createObjectURL(new Blob([bytes], { type: 'image/png' }));
      resolved.set(avatarUrl, objectUrl);
      while (resolved.size > MAX_CACHED_AVATARS) {
        const [oldestUrl, oldestObject] = resolved.entries().next().value as [string, string];
        URL.revokeObjectURL(oldestObject);
        resolved.delete(oldestUrl);
        cache.delete(oldestUrl);
      }
      return objectUrl;
    })
    .catch(() => {
      if (cache.get(avatarUrl) === pending) cache.delete(avatarUrl);    // a later render may retry
      return null;
    });
  cache.set(avatarUrl, pending);
  return pending;
}

/** Object URL for a member's avatar, or null while loading, hidden or absent. */
export function useAvatarSource(avatarUrl: string | null | undefined, hidden = false): string | null {
  const [source, setSource] = useState<string | null>(() => (avatarUrl && !hidden ? resolved.get(avatarUrl) ?? null : null));
  useEffect(() => {
    if (!avatarUrl || hidden) {
      setSource(null);
      return;
    }
    let active = true;
    setSource(resolved.get(avatarUrl) ?? null);
    void loadAvatar(avatarUrl).then((objectUrl) => { if (active) setSource(objectUrl); });
    return () => { active = false; };
  }, [avatarUrl, hidden]);
  return source;
}

/** Drop every cached image and every fetch not yet sent (sign-out). */
export function clearAvatarCache(): void {
  generation += 1;
  // A waiter holds no slot until it starts, so cancelling one frees nothing.
  for (const waiter of waiting.splice(0)) waiter.cancel();
  for (const objectUrl of resolved.values()) URL.revokeObjectURL(objectUrl);
  resolved.clear();
  cache.clear();
}
