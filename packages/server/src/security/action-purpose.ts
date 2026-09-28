import { createHash } from 'node:crypto';
import { canonicalActionBody } from '@alparts/shared';

export function actionPurpose(method: string, path: string, body: unknown): string {
  return `${method} ${path} ${createHash('sha256').update(canonicalActionBody(body)).digest('base64url')}`;
}
