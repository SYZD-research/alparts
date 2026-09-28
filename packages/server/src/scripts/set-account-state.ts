import { closeDb } from '../db/index.js';
import { setAccountDisabled } from '../services/account-state.service.js';
import { withOperatorMutation } from '../security/runtime-lease.js';
import { verifyAuditChain } from '../middleware/audit.js';

const [operation, userId, ...extra] = process.argv.slice(2);
try {
  if (extra.length || !['disable', 'enable'].includes(operation) || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(userId ?? '')) {
    throw new Error('Usage: set-account-state <disable|enable> <user UUID>');
  }
  await withOperatorMutation(async () => {
    if (!(await verifyAuditChain()).valid) throw new Error('AUDIT_CHAIN_INVALID');
    await setAccountDisabled(userId, operation === 'disable');
  });
  process.stdout.write(`Account ${operation} completed.\n`);
} finally {
  await closeDb();
}
