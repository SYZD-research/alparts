const AUTHORIZATION_REVISION_PATTERN = /^[a-f0-9]{64}$/;

export function withExpectedAuthorizationRevision<T extends Record<string, unknown>>(
  input: T,
  authorizationRevision: string,
): T & { expectedAuthorizationRevision: string } {
  if (!AUTHORIZATION_REVISION_PATTERN.test(authorizationRevision)) {
    throw new Error('Authorization preview revision is invalid');
  }
  return { ...input, expectedAuthorizationRevision: authorizationRevision };
}

export function isStaleAuthorizationPreviewError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const candidate = error as { status?: unknown; code?: unknown };
  return candidate.status === 409 && candidate.code === 'STALE_PREVIEW';
}
