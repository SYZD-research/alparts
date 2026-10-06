import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Attachment, Message, SignedAttachmentEnvelope } from '@alparts/shared';

const mocks = vi.hoisted(() => ({
  getChannelDeviceDirectory: vi.fn(),
  verifyAttachmentSignature: vi.fn(),
}));

vi.mock('./api', () => ({ api: { getChannelDeviceDirectory: mocks.getChannelDeviceDirectory } }));
vi.mock('./crypto.service', () => ({
  getChannelKeyForVersion: vi.fn(),
  verifyAttachmentSignature: mocks.verifyAttachmentSignature,
}));

const {
  ATTACHMENT_CHUNK_AAD_FORMAT,
  ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  clearAttachmentVerificationCache,
  encodeCanonicalBase64,
  verifyAttachmentMetadata,
} = await import('./attachment-crypto.service');
const { markMessageCryptoVerification } = await import('../stores/message-projector');

const uploadId = '11111111-1111-4111-8111-111111111111';
const messageId = '22222222-2222-4222-8222-222222222222';
const channelId = '44444444-4444-4444-8444-444444444444';
const deviceId = '55555555-5555-4555-8555-555555555555';
const authorId = '66666666-6666-4666-8666-666666666666';

const baseMessage = { id: messageId, channelId, authorId, keyVersion: 1, idempotencyKey: 'message-signed-key' };
const verified = markMessageCryptoVerification(baseMessage as Message, true);

function attachment(): Attachment {
  const noncePrefix = encodeCanonicalBase64(new Uint8Array(8).fill(3));
  const size = 4 + ATTACHMENT_GCM_TAG_BYTES;
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
    sizeBytes: size,
    ciphertextSizeBytes: size,
    plaintextSizeBytes: 4,
    chunkCount: 1,
    wrappedKey: encodeCanonicalBase64(new Uint8Array(60)),
    contentNonce: noncePrefix,
    cryptoManifest: {
      version: 1,
      algorithm: 'AES-256-GCM',
      nonceStrategy: 'prefix-counter-be32',
      noncePrefix,
      aadVersion: 1,
      plaintextSize: 4,
      chunkPlaintextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
      authenticationTagBytes: ATTACHMENT_GCM_TAG_BYTES,
      chunkCount: 1,
      uploadId,
      messageId,
      aadFormat: ATTACHMENT_CHUNK_AAD_FORMAT,
    },
    thumbnailKey: null,
    createdAt: '2026-08-26T00:00:00.000Z',
  };
}

describe('attachment binding to its message', () => {
  beforeEach(() => {
    clearAttachmentVerificationCache();
    mocks.getChannelDeviceDirectory.mockReset();
    mocks.getChannelDeviceDirectory.mockResolvedValue([{ deviceId, userId: authorId, identityKey: 'identity' }]);
    mocks.verifyAttachmentSignature.mockReset();
  });

  it('opens a file only for a verified message', async () => {
    mocks.verifyAttachmentSignature.mockResolvedValue(true);
    await expect(verifyAttachmentMetadata(baseMessage, attachment())).rejects.toThrow(/メッセージを確認できない/);
    expect(mocks.verifyAttachmentSignature).not.toHaveBeenCalled();
  });

  it('accepts a file signed for the message key', async () => {
    mocks.verifyAttachmentSignature.mockImplementation(async (envelope: SignedAttachmentEnvelope) => (
      envelope.messageIdempotencyKey === 'message-signed-key'
    ));
    const envelope = await verifyAttachmentMetadata(verified, attachment());
    expect(envelope.messageIdempotencyKey).toBe('message-signed-key');
  });

  it('still accepts a file signed before the binding existed', async () => {
    mocks.verifyAttachmentSignature.mockImplementation(async (envelope: SignedAttachmentEnvelope) => (
      envelope.messageIdempotencyKey === undefined
    ));
    const envelope = await verifyAttachmentMetadata(verified, attachment());
    expect(envelope.messageIdempotencyKey).toBeUndefined();
  });

  it('refuses a file signed for another message', async () => {
    mocks.verifyAttachmentSignature.mockImplementation(async (envelope: SignedAttachmentEnvelope) => (
      envelope.messageIdempotencyKey === 'another-message-key'
    ));
    await expect(verifyAttachmentMetadata(verified, attachment())).rejects.toThrow(/検証できませんでした/);
  });
});
