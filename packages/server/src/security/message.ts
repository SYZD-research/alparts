import { createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import {
  serializeAttachmentEnvelope,
  serializeDeviceChallengeProof,
  serializeChannelKeyAcknowledgement,
  serializeChannelKeyEpochAbort,
  serializeChannelKeyFreshStart,
  serializeChannelKeyWrap,
  serializeMessageEnvelope,
  type SignedAttachmentEnvelope,
  type SignedMessageEnvelope,
  type SignedChannelKeyWrap,
  type SignedChannelKeyAcknowledgement,
  type SignedChannelKeyEpochAbort,
  type SignedChannelKeyFreshStart,
} from '@alparts/shared';

const base64Url = z.string().min(1).max(2048).regex(/^[A-Za-z0-9_-]+$/);
const publicBundleSchema = z.object({
  version: z.literal(1),
  encryptionKey: z.object({
    kty: z.literal('RSA'),
    n: base64Url,
    e: base64Url,
    alg: z.literal('RSA-OAEP-256'),
    ext: z.literal(true).optional(),
    key_ops: z.array(z.literal('encrypt')).length(1).optional(),
  }).strict(),
  signingKey: z.object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: base64Url,
    y: base64Url,
    alg: z.literal('ES256'),
    ext: z.literal(true).optional(),
    key_ops: z.array(z.literal('verify')).length(1).optional(),
  }).strict(),
}).strict();

export type DevicePublicBundle = z.infer<typeof publicBundleSchema>;

export function parseDevicePublicBundle(value: string): DevicePublicBundle {
  if (Buffer.byteLength(value, 'utf8') > 16 * 1024) throw new Error('INVALID_IDENTITY_KEY');
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('INVALID_IDENTITY_KEY');
  }
  const result = publicBundleSchema.safeParse(parsed);
  if (!result.success) throw new Error('INVALID_IDENTITY_KEY');

  // Importing both keys catches malformed curve/RSA points that match the JSON shape.
  // Constrain RSA work so a malicious recipient cannot force every sender to
  // perform pathological public-key operations during channel fanout.
  try {
    const encryptionKey = createPublicKey({ key: result.data.encryptionKey as any, format: 'jwk' });
    const signingKey = createPublicKey({ key: result.data.signingKey as any, format: 'jwk' });
    const modulusLength = encryptionKey.asymmetricKeyDetails?.modulusLength;
    if (!modulusLength || modulusLength < 2048 || modulusLength > 4096) throw new Error('invalid RSA size');
    if (result.data.encryptionKey.e !== 'AQAB') throw new Error('invalid RSA exponent');
    if (signingKey.asymmetricKeyType !== 'ec') throw new Error('invalid signing key');
  } catch {
    throw new Error('INVALID_IDENTITY_KEY');
  }
  return result.data;
}

export function canonicalDeviceIdentityKey(value: string): string {
  const bundle = parseDevicePublicBundle(value);
  return JSON.stringify({
    version: bundle.version,
    encryptionKey: {
      kty: bundle.encryptionKey.kty,
      n: bundle.encryptionKey.n,
      e: bundle.encryptionKey.e,
      alg: bundle.encryptionKey.alg,
      ext: true,
      key_ops: ['encrypt'],
    },
    signingKey: {
      kty: bundle.signingKey.kty,
      crv: bundle.signingKey.crv,
      x: bundle.signingKey.x,
      y: bundle.signingKey.y,
      alg: bundle.signingKey.alg,
      ext: true,
      key_ops: ['verify'],
    },
  });
}

export function verifyDeviceChallengeSignature(
  identityKey: string,
  userId: string,
  challenge: string,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeDeviceChallengeProof(userId, challenge), signature);
}

export function verifyChannelKeyWrapSignature(
  identityKey: string,
  envelope: SignedChannelKeyWrap,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeChannelKeyWrap(envelope), signature);
}

export function verifyChannelKeyAcknowledgementSignature(
  identityKey: string,
  envelope: SignedChannelKeyAcknowledgement,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeChannelKeyAcknowledgement(envelope), signature);
}

export function verifyChannelKeyEpochAbortSignature(
  identityKey: string,
  envelope: SignedChannelKeyEpochAbort,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeChannelKeyEpochAbort(envelope), signature);
}

export function verifyChannelKeyFreshStartSignature(
  identityKey: string,
  envelope: SignedChannelKeyFreshStart,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeChannelKeyFreshStart(envelope), signature);
}

export function verifyMessageEnvelopeSignature(
  identityKey: string,
  envelope: SignedMessageEnvelope,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeMessageEnvelope(envelope), signature);
}

export function verifyAttachmentEnvelopeSignature(
  identityKey: string,
  envelope: SignedAttachmentEnvelope,
  signature: string,
): boolean {
  return verifyDeviceSignature(identityKey, serializeAttachmentEnvelope(envelope), signature);
}

function verifyDeviceSignature(identityKey: string, payload: string, signature: string): boolean {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signature)) return false;
  const bundle = parseDevicePublicBundle(identityKey);
  const key = createPublicKey({ key: bundle.signingKey as any, format: 'jwk' });
  return verify(
    'sha256',
    Buffer.from(payload, 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64'),
  );
}
