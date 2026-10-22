import { normalizeServerUrl } from './security-policy.js';

/** The part of Electron's cookie store that sign-out uses. */
export interface CookieStore {
  get(filter: { url: string }): Promise<ReadonlyArray<{ name: string }>>;
  remove(url: string, name: string): Promise<void>;
  flushStore(): Promise<void>;
}

/**
 * Drops every cookie the given deployments set. The session cookie is HttpOnly,
 * so the page cannot remove it, and a sign-out the server did not confirm would
 * otherwise leave it for the next start to resume.
 */
export async function clearDeploymentCookies(
  cookies: CookieStore,
  serverUrls: ReadonlyArray<string | null>,
): Promise<void> {
  const origins = new Set(serverUrls.filter((url): url is string => url !== null).map(normalizeServerUrl));
  for (const origin of origins) {
    const stored = await cookies.get({ url: origin });
    await Promise.all(stored.map(({ name }) => cookies.remove(origin, name)));
  }
  // The store writes removals to disk lazily; a quit right after sign-out must not bring the cookie back.
  await cookies.flushStore();
}
