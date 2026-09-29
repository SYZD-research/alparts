// Loaded from a file (never from an eval string) so that the production
// runtime can keep --disallow-code-generation-from-strings enabled.
import { parentPort } from 'node:worker_threads';
import bcrypt from 'bcryptjs';

const SALT_PATTERN = /^\$2[aby]\$(12|13|14|15)\$[./A-Za-z0-9]{22}$/;

interface PasswordWorkerTask {
  id: number;
  kind: 'hash' | 'derive';
  password: string;
  rounds?: number;
  salt?: string;
}

function run(task: PasswordWorkerTask): string {
  if (!task || !Number.isSafeInteger(task.id) || typeof task.password !== 'string') {
    throw new Error('INVALID_PASSWORD_TASK');
  }
  const passwordBytes = Buffer.byteLength(task.password, 'utf8');
  if (passwordBytes < 1 || passwordBytes > 72) throw new Error('INVALID_PASSWORD_TASK');
  if (task.kind === 'hash') {
    const rounds = task.rounds;
    if (typeof rounds !== 'number' || !Number.isSafeInteger(rounds) || rounds < 12 || rounds > 15) {
      throw new Error('INVALID_PASSWORD_TASK');
    }
    return bcrypt.hashSync(task.password, rounds);
  }
  if (task.kind === 'derive') {
    if (typeof task.salt !== 'string' || !SALT_PATTERN.test(task.salt)) throw new Error('INVALID_PASSWORD_TASK');
    return bcrypt.hashSync(task.password, task.salt);
  }
  throw new Error('INVALID_PASSWORD_TASK');
}

if (!parentPort) throw new Error('PASSWORD_WORKER_CONTEXT');
const port = parentPort;
port.on('message', (task: PasswordWorkerTask) => {
  try {
    port.postMessage({ id: task.id, ok: true, value: run(task) });
  } catch {
    port.postMessage({ id: task && task.id, ok: false });
  }
});
