import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Images pinned by digest. PostgreSQL and the object store are the ones
 * docker-compose.yml runs for development (a test keeps them equal); the
 * server accepts PostgreSQL 16 only.
 */
export const IMAGES = {
  postgres: 'postgres:16.15-alpine3.23@sha256:731499cca67dd6cbb34bbffbf489bda72aa31252b14bcc0eafdccbb92c4b2446',
  objectStorage: 'chrislusf/seaweedfs:4.53@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0',
  proxy: 'caddy:2.11.9-alpine@sha256:71d41fe4b1ae92a058abc87afe614178b996d8a6b96d0f4c71ae30606e5927e3',
} as const;

export const BACKUP_TOOLS_DIR = join('setup', 'backup-tools');

/** Named after its Dockerfile's content, so a changed Dockerfile builds a new image. */
export function backupToolsImage(repo: string): string {
  const dockerfile = readFileSync(join(repo, BACKUP_TOOLS_DIR, 'Dockerfile'));
  return `alparts-backup-tools:${createHash('sha256').update(dockerfile).digest('hex').slice(0, 12)}`;
}
