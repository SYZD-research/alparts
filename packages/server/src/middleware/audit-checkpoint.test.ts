import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';

describe('required audit checkpoint', () => {
  it('fails readiness when the checkpoint is absent, including an empty audit database', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'alparts-audit-checkpoint-'));
    process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
    process.env.AUDIT_CHECKPOINT_PATH = join(directory, 'missing.json');
    try {
      const { checkAuditCheckpoint } = await import('./audit.js');
      await assert.rejects(checkAuditCheckpoint(), /not provisioned|missing/i);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
