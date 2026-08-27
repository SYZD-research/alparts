import { closeDb } from '../db/index.js';
import { provisionAuditCheckpoint } from '../middleware/audit.js';

try {
  await provisionAuditCheckpoint();
  process.stdout.write('Audit checkpoint provisioned and verified.\n');
} finally {
  await closeDb();
}
