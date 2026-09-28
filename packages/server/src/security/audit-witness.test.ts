import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { it } from 'node:test';
import { serializeAuditWitness, verifyAuditWitness, type AuditWitnessPayload } from './audit-witness.js';

it('verifies an independent SLH-DSA anchor and rejects forgery, cross-deployment use and expiry', () => {
  const keys = generateKeyPairSync('slh-dsa-sha2-256s');
  const publicKey = String(keys.publicKey.export({ format: 'pem', type: 'spki' }));
  const now = Date.now();
  const payload: AuditWitnessPayload = { version: 1, algorithm: 'SLH-DSA-SHA2-256s',
    deploymentId: randomUUID(), logId: randomUUID(), logHash: 'ab'.repeat(32),
    logCreatedAt: new Date(now - 1000).toISOString(), issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 3600_000).toISOString() };
  const envelope = { payload, signature: sign(null, serializeAuditWitness(payload), keys.privateKey).toString('base64') };
  assert.deepEqual(verifyAuditWitness(envelope, publicKey, payload.deploymentId, now), payload);
  assert.throws(() => verifyAuditWitness(envelope, publicKey, randomUUID(), now));
  assert.throws(() => verifyAuditWitness(envelope, publicKey, payload.deploymentId, now + 3600_000));
  assert.throws(() => verifyAuditWitness({ ...envelope, payload: { ...payload, logHash: 'cd'.repeat(32) } }, publicKey, payload.deploymentId, now));
  const other = generateKeyPairSync('slh-dsa-sha2-256s');
  assert.throws(() => verifyAuditWitness(envelope, String(other.publicKey.export({ format: 'pem', type: 'spki' })), payload.deploymentId, now));
});
