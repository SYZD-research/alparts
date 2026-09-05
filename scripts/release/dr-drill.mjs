import { spawn } from 'node:child_process';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { artifactDigest } from './update-manifest.mjs';

const [backup, report] = process.argv.slice(2);
if (!backup || !report) throw new Error('Usage: dr-drill.mjs encrypted-backup.tar.age new-report.json');
// Target approval, empty-target checks, archive validation and reference/checksum
// reconciliation are enforced by the existing restore tool, without weakening it.
const digest = await artifactDigest(backup);
const reportPath = resolve(report);
const reportFile = await open(reportPath, 'wx', 0o600);
const log = await open(`${reportPath}.log`, 'wx', 0o600);
const start = Date.now();
let exitCode = null;
let signal = null;
try {
  const script = fileURLToPath(new URL('../restore-verify.sh', import.meta.url));
  const child = spawn('bash', [script, resolve(backup)], {
    stdio: ['ignore', log.fd, log.fd], timeout: 4 * 60 * 60 * 1000, killSignal: 'SIGTERM',
  });
  const result = await new Promise((resolveResult, reject) => {
    child.once('error', reject);
    child.once('exit', (code, terminatedBy) => resolveResult({ code, terminatedBy }));
  });
  exitCode = result.code; signal = result.terminatedBy;
} finally {
  await log.close();
  await reportFile.writeFile(`${JSON.stringify({ version: 1, startedAt: new Date(start).toISOString(),
    completedAt: new Date().toISOString(), backupSha256: digest.sha256,
    restoreVerified: exitCode === 0, exitCode, signal, elapsedSeconds: (Date.now() - start) / 1000,
    scope: 'isolated restore, row counts, references and object checksums; excludes service recovery, PITR and site failover',
  }, null, 2)}\n`);
  await reportFile.close();
}
if (exitCode !== 0) process.exitCode = 1;
console.log(exitCode === 0 ? 'Isolated restore verified; drill report saved.' : 'Restore drill failed; inspect the private report and log.');
