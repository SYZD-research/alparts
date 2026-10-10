import { z } from 'zod';

/**
 * Ids are stored as PostgreSQL uuid and come back as lowercase text, and the
 * server compares them as text: audit-log scopes, authorization snapshots and
 * realtime room names. An id in another letter case still finds its row, but
 * would be recorded and compared as given, so only the lowercase form is
 * accepted from clients.
 */
export const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ANY_CASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const canonicalUuid = z.string().regex(CANONICAL_UUID);

/** True when a path segment names an id in another letter case than the stored one. */
export function hasNonCanonicalUuid(path: string): boolean {
  for (const raw of path.split('/')) {
    let segment: string;
    try {
      segment = decodeURIComponent(raw);
    } catch {
      continue;
    }
    if (ANY_CASE_UUID.test(segment) && !CANONICAL_UUID.test(segment)) return true;
  }
  return false;
}
