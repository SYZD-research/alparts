import { closeDb } from '../db/index.js';
import { resetPassword } from '../services/account-state.service.js';
import { hashNewPassword } from '../services/auth.service.js';
import { closePasswordWorkers } from '../security/password-work.js';
import { withOperatorMutation } from '../security/runtime-lease.js';
import { verifyAuditChain } from '../middleware/audit.js';

// The new password comes from standard input, never from arguments, so it
// does not appear in process listings or shell history.
async function readPassword(): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > 1024) throw new Error('The password is too long');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

// The password workers do not hold the process open on their own.
async function keepingProcessAlive<T>(work: Promise<T>): Promise<T> {
  const timer = setInterval(() => undefined, 1_000);
  try {
    return await work;
  } finally {
    clearInterval(timer);
  }
}

const [userId, ...extra] = process.argv.slice(2);
try {
  if (extra.length || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(userId ?? '')) {
    throw new Error('Usage: reset-password <user UUID> < new-password-file');
  }
  const passwordHash = await keepingProcessAlive(hashNewPassword(await readPassword())).catch((error: unknown) => {
    if (error instanceof Error && error.message === 'INVALID_PASSWORD_LENGTH') {
      throw new Error('The new password must be 12 to 72 bytes');
    }
    throw error;
  });
  const { passkeysRemoved } = await withOperatorMutation(async () => {
    if (!(await verifyAuditChain()).valid) throw new Error('AUDIT_CHAIN_INVALID');
    return resetPassword(userId, passwordHash);
  });
  process.stdout.write('Password reset completed. Every session of the account was signed out'
    + ` and ${passkeysRemoved} passkey(s) were removed. Ask the user to sign in with the new password,`
    + ' revoke devices they do not recognize, and register a passkey again.\n');
} finally {
  await closePasswordWorkers();
  await closeDb();
}
