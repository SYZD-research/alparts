import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { eq } from 'drizzle-orm';

const enabled = process.env.RUN_INTEGRATION === '1';

describe('audit checkpoint write failure admission', { skip: !enabled }, () => {
  let checkpointDirectory = '';
  let checkpointPath = '';
  let closeDb: typeof import('../db/index.js').closeDb;

  before(async () => {
    checkpointDirectory = await mkdtemp(join(tmpdir(), 'alparts-audit-write-failure-'));
    checkpointPath = join(checkpointDirectory, 'checkpoint.json');
    process.env.AUDIT_CHECKPOINT_PATH = checkpointPath;
    process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
    const audit = await import('../middleware/audit.js');
    closeDb = (await import('../db/index.js')).closeDb;
    await audit.provisionAuditCheckpoint();
  });

  after(async () => {
    if (checkpointDirectory) await chmod(checkpointDirectory, 0o700).catch(() => undefined);
    await closeDb?.();
    if (checkpointDirectory) await rm(checkpointDirectory, { recursive: true, force: true });
  });

  it('returns the committed result once, then fails later audited writes closed', async () => {
    const audit = await import('../middleware/audit.js');
    const { db } = await import('../db/index.js');
    const { auditLogs } = await import('../db/schema.js');
    const checkpointBefore = await readFile(checkpointPath, 'utf8');
    const firstAction = `security.audit.checkpoint-write-failure-control.${randomUUID()}`;
    const deniedAction = `security.audit.must-not-commit.${randomUUID()}`;

    await chmod(checkpointDirectory, 0o500);
    const firstResult = await audit.auditedTransaction(async () => firstAction, () => ({
      action: firstAction,
      targetType: 'system',
    }));

    assert.equal(firstResult, firstAction);
    assert.ok(await db.query.auditLogs.findFirst({ where: eq(auditLogs.action, firstAction) }));
    assert.equal(await readFile(checkpointPath, 'utf8'), checkpointBefore);

    let deniedOperationRan = false;
    await assert.rejects(audit.auditedTransaction(async () => {
      deniedOperationRan = true;
      return deniedAction;
    }, () => ({
      action: deniedAction,
      targetType: 'system',
    })), (error: unknown) => error instanceof audit.AuditUnavailableError);

    assert.equal(deniedOperationRan, false);
    assert.equal(await db.query.auditLogs.findFirst({ where: eq(auditLogs.action, deniedAction) }), undefined);

    let deniedGuardedOperationRan = false;
    await assert.rejects(audit.auditGuardedTransaction(async () => {
      deniedGuardedOperationRan = true;
      return 'must-not-run';
    }), (error: unknown) => error instanceof audit.AuditUnavailableError);
    assert.equal(deniedGuardedOperationRan, false);
    await assert.rejects(
      audit.assertAuditWriteAvailable(),
      (error: unknown) => error instanceof audit.AuditUnavailableError,
    );
    await assert.rejects(audit.checkAuditCheckpoint());
  });
});
