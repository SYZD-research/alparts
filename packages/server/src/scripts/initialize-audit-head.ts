import { closeDb } from '../db/index.js';
import { provisionAuditHead } from '../middleware/audit.js';

try {
  await provisionAuditHead();
  process.stdout.write('Durable audit head provisioned and verified.\n');
} finally {
  await closeDb();
}
