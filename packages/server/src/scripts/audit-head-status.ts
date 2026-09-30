import { stat } from 'node:fs/promises';
import { config } from '../config/index.js';
import { readStoredAuditHead } from '../services/object-storage.js';

// Read-only probe for dev.sh. Prints "pending" when an existing checkpoint
// still lacks its durable head, i.e. the one-time audit:head:init migration
// has not been run; otherwise "ok".
async function checkpointExists(path: string | null): Promise<boolean> {
  if (!path) return false;
  try {
    return (await stat(path)).isFile();
  } catch (error: any) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

const pending = config.audit.headObjectKey !== null
  && await checkpointExists(config.audit.checkpointPath)
  && await readStoredAuditHead() === null;
process.stdout.write(pending ? 'pending\n' : 'ok\n');
process.exit(0);
