import { describe, expect, it } from 'vitest';
import {
  MAX_FILE_SIZE,
  serializeAttachmentEnvelope,
  type Attachment,
  type SignedAttachmentEnvelope,
} from '@alparts/shared';
import {
  ApiError,
  type AttachmentUploadCreateInput,
  type AttachmentUploadReservation,
} from './api';
import {
  ATTACHMENT_CHUNK_AAD_FORMAT,
  ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  attachmentChunkAad,
  attachmentChunkCount,
  attachmentChunkNonce,
  attachmentCiphertextChunkSize,
  buildSignedAttachmentEnvelope,
  decryptAttachmentChunk,
  encodeCanonicalBase64,
  encryptAttachmentChunk,
  isDangerousAttachmentFilename,
  validateAttachmentManifest,
} from './attachment-crypto.service';
import {
  assertAttachmentReservationContract,
  cancelAttachmentReservationBestEffort,
  createAttachmentReservationWithRetry,
  isExpiredKnownAttachmentReservation,
  attachmentExpiryRecoveryPlan,
  isTransientAttachmentError,
} from './attachment-transfer.service';
import { isRevokedIdentityRegistrationError, verifyAttachmentSignature } from './crypto.service';
import { safeMarkdownHref } from './url-policy';

const uploadId = '11111111-1111-4111-8111-111111111111';
const messageId = '22222222-2222-4222-8222-222222222222';
const channelId = '44444444-4444-4444-8444-444444444444';
const deviceId = '55555555-5555-4555-8555-555555555555';
const authorId = '66666666-6666-4666-8666-666666666666';

describe('attachment crypto protocol', () => {
  it('serializes the exact NUL-delimited AAD and big-endian counter nonce', () => {
    const aad = new TextDecoder().decode(attachmentChunkAad(uploadId, messageId, 0x01020304, 7, 12345));
    expect(aad).toBe([
      'alparts-attachment-chunk-v1',
      uploadId,
      messageId,
      '16909060',
      '7',
      '12345',
    ].join('\0'));

    const prefix = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
    expect([...attachmentChunkNonce(prefix, 0x01020304)])
      .toEqual([0, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4]);
  });

  it('uses deterministic 5MiB layout including an authenticated empty file', () => {
    expect(attachmentChunkCount(0)).toBe(1);
    expect(attachmentCiphertextChunkSize(0, 0)).toBe(ATTACHMENT_GCM_TAG_BYTES);
    expect(attachmentChunkCount(ATTACHMENT_PLAINTEXT_CHUNK_BYTES + 1)).toBe(2);
    expect(attachmentCiphertextChunkSize(ATTACHMENT_PLAINTEXT_CHUNK_BYTES + 1, 1)).toBe(17);
    expect(attachmentChunkCount(MAX_FILE_SIZE)).toBe(20);
  });

  it('round-trips a chunk and rejects a manifest size mismatch', async () => {
    const raw = new Uint8Array(32);
    raw.fill(7);
    const key = await crypto.subtle.importKey('raw', raw.buffer, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    raw.fill(0);
    const prefix = new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]);
    const plaintext = new TextEncoder().encode('chunk plaintext');
    const ciphertext = await encryptAttachmentChunk(
      plaintext.buffer,
      key,
      prefix,
      uploadId,
      messageId,
      0,
      1,
      plaintext.byteLength,
    );
    const attachment = attachmentFixture(plaintext.byteLength, prefix);
    const manifest = validateAttachmentManifest(attachment, messageId);
    expect(new TextDecoder().decode(await decryptAttachmentChunk(ciphertext, key, manifest, 0)))
      .toBe('chunk plaintext');
    expect(() => validateAttachmentManifest({ ...attachment, sizeBytes: attachment.sizeBytes + 1 }, messageId))
      .toThrow(/一致/);
  });

  it('warns for active, executable, macro, and archive extensions even behind a benign suffix', () => {
    expect(isDangerousAttachmentFilename('report.pdf')).toBe(true);
    expect(isDangerousAttachmentFilename('photo.png.exe')).toBe(true);
    expect(isDangerousAttachmentFilename('quarterly.XLSM')).toBe(true);
    expect(isDangerousAttachmentFilename('payload.svg.txt')).toBe(true);
    expect(isDangerousAttachmentFilename('notes.txt')).toBe(false);
  });

  it('verifies the canonical sender envelope and fails closed on tampering or legacy metadata', async () => {
    const attachment = attachmentFixture(17, new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));
    const message = { id: messageId, channelId, authorId, keyVersion: 1, idempotencyKey: 'message-signed-key' };
    const envelope = buildSignedAttachmentEnvelope(message, attachment);
    expect(envelope.messageIdempotencyKey).toBe('message-signed-key');
    const signing = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey('jwk', signing.publicKey);
    publicJwk.alg = 'ES256';
    const signature = encodeCanonicalBase64(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signing.privateKey,
      new TextEncoder().encode(serializeAttachmentEnvelope(envelope)),
    ));
    const identityKey = JSON.stringify({
      version: 1,
      encryptionKey: {},
      signingKey: publicJwk,
    });

    expect(await verifyAttachmentSignature(envelope, signature, identityKey)).toBe(true);
    expect(await verifyAttachmentSignature(
      { ...envelope, plaintextSize: envelope.plaintextSize + 1 },
      signature,
      identityKey,
    )).toBe(false);
    expect(await verifyAttachmentSignature(
      { ...envelope, authorId: '77777777-7777-4777-8777-777777777777' },
      signature,
      identityKey,
    )).toBe(false);
    // Another message under the same id, or the unbound legacy layout, does not verify.
    expect(await verifyAttachmentSignature(
      { ...envelope, messageIdempotencyKey: 'another-message-key' },
      signature,
      identityKey,
    )).toBe(false);
    const { messageIdempotencyKey: _bound, ...legacy } = envelope;
    expect(await verifyAttachmentSignature(legacy as SignedAttachmentEnvelope, signature, identityKey)).toBe(false);
    // A message stored without a signed idempotency key has no files.
    expect(() => buildSignedAttachmentEnvelope({ ...message, idempotencyKey: '' }, attachment)).toThrow(/ファイル情報/);
    expect(() => buildSignedAttachmentEnvelope(message, { ...attachment, channelId: null }))
      .toThrow(/ファイル情報/);
    expect(() => buildSignedAttachmentEnvelope(message, { ...attachment, keyVersion: 2 }))
      .toThrow(/ファイル情報/);
    expect(() => buildSignedAttachmentEnvelope(message, {
      ...attachment,
      signature: encodeCanonicalBase64(new Uint8Array(63)),
    })).toThrow(/正しい形式のデータではありません/);
  });
});

describe('attachment transfer policy', () => {
  it('fails closed when reservation crypto parameters drift', () => {
    const reservation = reservationFixture();
    expect(() => assertAttachmentReservationContract(reservation, 42)).not.toThrow();
    expect(() => assertAttachmentReservationContract({
      ...reservation,
      crypto: { ...reservation.crypto, aadFormat: 'other' },
    }, 42)).toThrow(/取り決め/);
  });

  it('retries only transient transport statuses and recognizes revoked identities exactly', () => {
    expect(isTransientAttachmentError(new ApiError('busy', 503, 'BUSY'))).toBe(true);
    expect(isTransientAttachmentError(new ApiError('forbidden', 403, 'FORBIDDEN'))).toBe(false);
    expect(isRevokedIdentityRegistrationError(new ApiError('revoked', 409, 'IDENTITY_REVOKED'))).toBe(true);
    expect(isRevokedIdentityRegistrationError(new ApiError('conflict', 409, 'OTHER'))).toBe(false);
  });

  it('allows ordinary external links and blocks active/local URL schemes', () => {
    expect(safeMarkdownHref('https://example.com/path')).toBe('https://example.com/path');
    expect(safeMarkdownHref('/relative')).toBe('/relative');
    expect(safeMarkdownHref('mailto:user@example.com')).toBe('mailto:user@example.com');
    expect(safeMarkdownHref('javascript:alert(1)')).toBeNull();
    expect(safeMarkdownHref('data:text/html,test')).toBeNull();
    expect(safeMarkdownHref('file:///etc/passwd')).toBeNull();
  });

  it('reuses the exact reservation body and idempotency key after ambiguous retry', async () => {
    const input: AttachmentUploadCreateInput = {
      messageId,
      filenameEnc: encodeCanonicalBase64(new Uint8Array(28)),
      mimeType: 'text/plain',
      idempotencyKey: uploadId,
    };
    const seen: AttachmentUploadCreateInput[] = [];
    let fail = true;
    const operation = async (fixedInput: AttachmentUploadCreateInput) => {
      seen.push(fixedInput);
      if (fail) throw new TypeError('response lost');
      return reservationFixture();
    };
    const firstController = new AbortController();
    await expect(createAttachmentReservationWithRetry(
      input,
      firstController.signal,
      operation,
      1,
      0,
    )).rejects.toThrow(/response lost/);
    fail = false;
    const secondController = new AbortController();
    await expect(createAttachmentReservationWithRetry(
      input,
      secondController.signal,
      operation,
      1,
      0,
    )).resolves.toMatchObject({ uploadId });
    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(input);
    expect(seen[1]).toBe(input);
    expect(seen[1]).toEqual(seen[0]);
  });

  it('cancels reservations best-effort and rotates only for explicit known 410 expiry', async () => {
    const calls: string[] = [];
    expect(await cancelAttachmentReservationBestEffort(undefined, async (id) => { calls.push(id); })).toBe(false);
    expect(await cancelAttachmentReservationBestEffort(uploadId, async (id) => { calls.push(id); })).toBe(true);
    expect(await cancelAttachmentReservationBestEffort(uploadId, async (id) => {
      calls.push(id);
      throw new TypeError('offline');
    })).toBe(false);
    expect(calls).toEqual([uploadId, uploadId]);
    expect(isExpiredKnownAttachmentReservation(new ApiError('expired', 410, 'UPLOAD_EXPIRED'), true)).toBe(true);
    expect(isExpiredKnownAttachmentReservation(new ApiError('expired before response', 410, 'UPLOAD_EXPIRED'), true)).toBe(true);
    expect(isExpiredKnownAttachmentReservation(new ApiError('generic conflict', 409, 'IDEMPOTENCY_CONFLICT'), true)).toBe(false);
    expect(isExpiredKnownAttachmentReservation(new ApiError('message missing', 404, 'NOT_FOUND'), true)).toBe(false);
    expect(isExpiredKnownAttachmentReservation(new ApiError('forbidden', 403, 'FORBIDDEN'), true)).toBe(false);
    expect(attachmentExpiryRecoveryPlan(new ApiError('expired', 410, 'UPLOAD_EXPIRED'), true, 0))
      .toEqual({ rotateMaterial: true, retryAutomatically: true });
    expect(attachmentExpiryRecoveryPlan(new ApiError('expired again', 410, 'UPLOAD_EXPIRED'), true, 1))
      .toEqual({ rotateMaterial: true, retryAutomatically: false });
    expect(attachmentExpiryRecoveryPlan(new ApiError('generic conflict', 409, 'IDEMPOTENCY_CONFLICT'), true, 0))
      .toEqual({ rotateMaterial: false, retryAutomatically: false });
  });
});

function attachmentFixture(plaintextSize: number, prefix: Uint8Array): Attachment {
  const chunkCount = attachmentChunkCount(plaintextSize);
  const ciphertextSize = plaintextSize + chunkCount * ATTACHMENT_GCM_TAG_BYTES;
  const noncePrefix = encodeCanonicalBase64(prefix);
  return {
    id: '33333333-3333-4333-8333-333333333333',
    messageId,
    channelId,
    keyVersion: 1,
    deviceId,
    signature: encodeCanonicalBase64(new Uint8Array(64)),
    filenameEnc: encodeCanonicalBase64(new Uint8Array(28)),
    mimeType: 'text/plain',
    dangerousMime: false,
    downloadPolicy: 'attachment-only',
    sizeBytes: ciphertextSize,
    ciphertextSizeBytes: ciphertextSize,
    plaintextSizeBytes: plaintextSize,
    chunkCount,
    wrappedKey: encodeCanonicalBase64(new Uint8Array(60)),
    contentNonce: noncePrefix,
    cryptoManifest: {
      version: 1,
      algorithm: 'AES-256-GCM',
      nonceStrategy: 'prefix-counter-be32',
      noncePrefix,
      aadVersion: 1,
      plaintextSize,
      chunkPlaintextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
      authenticationTagBytes: ATTACHMENT_GCM_TAG_BYTES,
      chunkCount,
      uploadId,
      messageId,
      aadFormat: ATTACHMENT_CHUNK_AAD_FORMAT,
    },
    thumbnailKey: null,
    createdAt: '2026-08-26T00:00:00.000Z',
  };
}

function reservationFixture(): AttachmentUploadReservation {
  return {
    uploadId,
    reused: false,
    expiresAt: '2026-08-27T00:00:00.000Z',
    chunkPlaintextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCiphertextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES + ATTACHMENT_GCM_TAG_BYTES,
    authenticationTagBytes: ATTACHMENT_GCM_TAG_BYTES,
    maxPlaintextBytes: MAX_FILE_SIZE,
    maxChunkCount: 20,
    crypto: {
      version: 1,
      algorithm: 'AES-256-GCM',
      nonceStrategy: 'prefix-counter-be32',
      noncePrefixBytes: 8,
      aadVersion: 1,
      aadFormat: ATTACHMENT_CHUNK_AAD_FORMAT,
    },
  };
}
