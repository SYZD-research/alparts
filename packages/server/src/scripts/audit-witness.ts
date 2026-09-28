// Run key generation and signing on an independently controlled offline host.
// This module deliberately has no runtime config, database or network imports.
import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { writeFile, stat } from 'node:fs/promises';
import { readWitnessFile, serializeAuditWitness, verifyAuditWitness, type AuditWitnessPayload } from '../security/audit-witness.js';

const [operation, ...args] = process.argv.slice(2);
if (operation === 'keygen' && args.length === 2) {
  const pair = generateKeyPairSync('slh-dsa-sha2-256s');
  await writeFile(args[0], pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  await writeFile(args[1], pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644, flag: 'wx' });
} else if (operation === 'sign' && args.length === 4) {
  const [privatePath, checkpointPath, deploymentId, output] = args;
  if (((await stat(privatePath)).mode & 0o077) !== 0) throw new Error('PRIVATE_KEY_PERMISSIONS');
  const privateKey = createPrivateKey(await readWitnessFile(privatePath, 4096));
  if (privateKey.asymmetricKeyType !== 'slh-dsa-sha2-256s') throw new Error('INVALID_WITNESS_KEY');
  const checkpoint = JSON.parse(await readWitnessFile(checkpointPath));
  if (checkpoint.version !== 2) throw new Error('CHECKPOINT_V2_REQUIRED');
  const now = Date.now();
  const payload: AuditWitnessPayload = { version: 1, algorithm: 'SLH-DSA-SHA2-256s', deploymentId,
    logId: checkpoint.logId, logHash: checkpoint.logHash, logCreatedAt: checkpoint.logCreatedAt,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 24 * 3600_000).toISOString() };
  const signature = sign(null, serializeAuditWitness(payload), privateKey).toString('base64');
  await writeFile(output, JSON.stringify({ payload, signature }) + '\n', { mode: 0o644, flag: 'wx' });
} else if (operation === 'verify' && args.length === 3) {
  const payload = verifyAuditWitness(JSON.parse(await readWitnessFile(args[1])), await readWitnessFile(args[0], 4096), args[2]);
  process.stdout.write(JSON.stringify(payload) + '\n');
} else throw new Error('Usage: audit-witness keygen PRIVATE PUBLIC | sign PRIVATE CHECKPOINT DEPLOYMENT_UUID OUTPUT | verify PUBLIC WITNESS DEPLOYMENT_UUID');
