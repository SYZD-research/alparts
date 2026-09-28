import { createPublicKey, verify } from 'node:crypto';
import { open } from 'node:fs/promises';
import { z } from 'zod';

const payloadSchema = z.object({
  version: z.literal(1),
  algorithm: z.literal('SLH-DSA-SHA2-256s'),
  deploymentId: z.string().uuid(),
  logId: z.string().uuid(),
  logHash: z.string().regex(/^[a-f0-9]{64}$/),
  logCreatedAt: z.string().datetime(),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
}).strict();
export type AuditWitnessPayload = z.infer<typeof payloadSchema>;
export function serializeAuditWitness(payload: AuditWitnessPayload): Buffer {
  const p = payloadSchema.parse(payload);
  return Buffer.from(JSON.stringify(['alparts-offline-audit-witness', p.version, p.algorithm,
    p.deploymentId, p.logId, p.logHash, p.logCreatedAt, p.issuedAt, p.expiresAt]));
}

export function verifyAuditWitness(input: unknown, publicKey: string, deploymentId: string, now = Date.now()): AuditWitnessPayload {
  const envelope = z.object({ payload: payloadSchema,
    signature: z.string().max(40_000).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  }).strict().parse(input);
  const p = envelope.payload;
  const issued = Date.parse(p.issuedAt);
  const expires = Date.parse(p.expiresAt);
  const key = createPublicKey(publicKey);
  const signature = Buffer.from(envelope.signature, 'base64');
  if (key.asymmetricKeyType !== 'slh-dsa-sha2-256s' || signature.length !== 29_792
    || p.deploymentId !== deploymentId || issued > now + 60_000 || expires <= now
    || expires <= issued || expires - issued > 7 * 24 * 3600_000 || Date.parse(p.logCreatedAt) > issued + 60_000
    || !verify(null, serializeAuditWitness(p), key, signature)) throw new Error('INVALID_AUDIT_WITNESS');
  return p;
}

export async function readWitnessFile(path: string, maxBytes = 64 * 1024): Promise<string> {
  const file = await open(path, 'r');
  try {
    const metadata = await file.stat();
    if (!metadata.isFile() || metadata.size > maxBytes || (metadata.mode & 0o022) !== 0) throw new Error('UNSAFE_AUDIT_WITNESS_FILE');
    const value = await file.readFile('utf8');
    if (Buffer.byteLength(value) > maxBytes) throw new Error('UNSAFE_AUDIT_WITNESS_FILE');
    return value;
  } finally { await file.close(); }
}
