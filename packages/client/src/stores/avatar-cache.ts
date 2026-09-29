import { useEffect, useState } from 'react';
import { api } from '../services/api';

// Avatar URLs change with every new image, so a fetched image never goes stale.
const MAX_CACHED_AVATARS = 200;
const cache = new Map<string, Promise<string | null>>();
const resolved = new Map<string, string>();

function load(avatarUrl: string): Promise<string | null> {
  const existing = cache.get(avatarUrl);
  if (existing) return existing;
  const pending = api.getAvatarBytes(avatarUrl)
    .then((bytes) => {
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
      cache.delete(avatarUrl);    // a later render may retry
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
    void load(avatarUrl).then((objectUrl) => { if (active) setSource(objectUrl); });
    return () => { active = false; };
  }, [avatarUrl, hidden]);
  return source;
}

/** Drop every cached image (sign-out). */
export function clearAvatarCache(): void {
  for (const objectUrl of resolved.values()) URL.revokeObjectURL(objectUrl);
  resolved.clear();
  cache.clear();
}
