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
  objectStorage: 'chrislusf/seaweedfs:4.52@sha256:57877e32bb90073b37dc109b438ba66e84fd5ed9ced5f5c04f56444ef243ce59',
  proxy: 'caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f',
} as const;

export const BACKUP_TOOLS_DIR = join('setup', 'backup-tools');

/** Named after its Dockerfile's content, so a changed Dockerfile builds a new image. */
export function backupToolsImage(repo: string): string {
  const dockerfile = readFileSync(join(repo, BACKUP_TOOLS_DIR, 'Dockerfile'));
  return `alparts-backup-tools:${createHash('sha256').update(dockerfile).digest('hex').slice(0, 12)}`;
}
