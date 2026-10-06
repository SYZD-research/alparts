import { createHash } from 'node:crypto';
import { canonicalActionBody } from '@alparts/shared';

// A purpose is stored with the step-up challenge and grant and sent back to
// the client. A fast digest of a password in it could be guessed offline, so
// password fields are left out; the grant still binds the method, the path
// and every other field.
const SECRET_FIELDS = ['password', 'newPassword', 'currentPassword'];

/** The part of a request body a step-up purpose binds. */
export function purposeFields(body: unknown): unknown {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return body;
  const rest: Record<string, unknown> = { ...(body as Record<string, unknown>) };
  for (const field of SECRET_FIELDS) delete rest[field];
  return rest;
}

export function actionPurpose(method: string, path: string, body: unknown): string {
  return `${method} ${path} ${createHash('sha256').update(canonicalActionBody(purposeFields(body))).digest('base64url')}`;
}
