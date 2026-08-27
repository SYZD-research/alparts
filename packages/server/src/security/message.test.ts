import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, webcrypto } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  ATTACHMENT_CHUNK_AAD_FORMAT,
  serializeAttachmentChunkAad,
  serializeAttachmentEnvelope,
  serializeAttachmentFilenameAad,
  serializeAttachmentWrappedKeyAad,
  serializeChannelKeyAcknowledgement,
  serializeChannelKeyEpochAbort,
  serializeChannelKeyWrap,
  serializeMessageAad,
  serializeMessageEnvelope,
  type SignedAttachmentEnvelope,
  type SignedMessageEnvelope,
} from '@alparts/shared';
import {
  parseDevicePublicBundle,
  canonicalDeviceIdentityKey,
  verifyAttachmentEnvelopeSignature,
  verifyChannelKeyWrapSignature,
  verifyChannelKeyAcknowledgementSignature,
  verifyChannelKeyEpochAbortSignature,
  verifyMessageEnvelopeSignature,
} from './message.js';

function fixture() {
  const encryption = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  const signing = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const encryptionJwk = encryption.publicKey.export({ format: 'jwk' });
  const signingJwk = signing.publicKey.export({ format: 'jwk' });
  encryptionJwk.alg = 'RSA-OAEP-256';
  signingJwk.alg = 'ES256';
  return {
    identityKey: JSON.stringify({ version: 1, encryptionKey: encryptionJwk, signingKey: signingJwk }),
    signingPrivateKey: signing.privateKey,
  };
}

describe('signed message envelopes', () => {
  it('keeps the protocol serialization vector stable', () => {
    const envelope: SignedMessageEnvelope = {
      type: 'message',
      channelId: '00000000-0000-4000-8000-000000000001',
      authorId: '00000000-0000-4000-8000-000000000004',
      deviceId: '00000000-0000-4000-8000-000000000002',
      encryptedContent: 'Y2lwaGVydGV4dA==',
      contentNonce: 'AAAAAAAAAAAAAAAA',
      keyVersion: 7,
      idempotencyKey: '00000000-0000-4000-8000-000000000003',
      refMessageId: null,
    };
    assert.equal(
      serializeMessageAad(envelope),
      '[2,"message","00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000002",7,"00000000-0000-4000-8000-000000000003",null]',
    );
    assert.equal(
      serializeMessageEnvelope(envelope),
      '[2,"message","00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000002",7,"00000000-0000-4000-8000-000000000003",null,"AAAAAAAAAAAAAAAA","Y2lwaGVydGV4dA=="]',
    );
  });

  it('accepts a valid P-256 device signature', () => {
    const keys = fixture();
    const envelope: SignedMessageEnvelope = {
      type: 'message',
      channelId: '00000000-0000-4000-8000-000000000001',
      authorId: '00000000-0000-4000-8000-000000000004',
      deviceId: '00000000-0000-4000-8000-000000000002',
      encryptedContent: Buffer.alloc(32, 7).toString('base64'),
      contentNonce: Buffer.alloc(12, 8).toString('base64'),
      keyVersion: 1,
      idempotencyKey: '00000000-0000-4000-8000-000000000003',
      refMessageId: null,
    };
    const signature = sign('sha256', Buffer.from(serializeMessageEnvelope(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyMessageEnvelopeSignature(keys.identityKey, envelope, signature), true);
  });

  it('binds the authenticated broadcast-mention bit in protocol v3', () => {
    const keys = fixture();
    const envelope: SignedMessageEnvelope = {
      type: 'message',
      channelId: '00000000-0000-4000-8000-000000000001',
      authorId: '00000000-0000-4000-8000-000000000004',
      deviceId: '00000000-0000-4000-8000-000000000002',
      encryptedContent: Buffer.alloc(32, 7).toString('base64'),
      contentNonce: Buffer.alloc(12, 8).toString('base64'),
      keyVersion: 1,
      idempotencyKey: '00000000-0000-4000-8000-000000000003',
      refMessageId: null,
      broadcastMention: false,
    };
    assert.match(serializeMessageEnvelope(envelope), /^\[3,/);
    const signature = sign('sha256', Buffer.from(serializeMessageEnvelope(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyMessageEnvelopeSignature(keys.identityKey, envelope, signature), true);
    assert.equal(verifyMessageEnvelopeSignature(keys.identityKey, { ...envelope, broadcastMention: true }, signature), false);
  });

  it('rejects ciphertext relocation and metadata tampering', () => {
    const keys = fixture();
    const envelope: SignedMessageEnvelope = {
      type: 'message',
      channelId: '00000000-0000-4000-8000-000000000001',
      authorId: '00000000-0000-4000-8000-000000000004',
      deviceId: '00000000-0000-4000-8000-000000000002',
      encryptedContent: Buffer.alloc(32, 7).toString('base64'),
      contentNonce: Buffer.alloc(12, 8).toString('base64'),
      keyVersion: 1,
      idempotencyKey: '00000000-0000-4000-8000-000000000003',
      refMessageId: null,
    };
    const signature = sign('sha256', Buffer.from(serializeMessageEnvelope(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    const mutations: SignedMessageEnvelope[] = [
      { ...envelope, type: 'edit' },
      { ...envelope, channelId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, authorId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, deviceId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, encryptedContent: Buffer.alloc(32, 9).toString('base64') },
      { ...envelope, contentNonce: Buffer.alloc(12, 9).toString('base64') },
      { ...envelope, keyVersion: 2 },
      { ...envelope, idempotencyKey: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, refMessageId: '00000000-0000-4000-8000-000000000099' },
    ];
    for (const mutation of mutations) {
      assert.equal(verifyMessageEnvelopeSignature(keys.identityKey, mutation, signature), false);
    }
  });

  it('rejects malformed public-key bundles', () => {
    assert.throws(() => parseDevicePublicBundle(JSON.stringify({ version: 1 })));
    const weakEncryption = generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 0x10001 });
    const signing = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const encryptionKey = weakEncryption.publicKey.export({ format: 'jwk' });
    const signingKey = signing.publicKey.export({ format: 'jwk' });
    encryptionKey.alg = 'RSA-OAEP-256';
    signingKey.alg = 'ES256';
    assert.throws(() => parseDevicePublicBundle(JSON.stringify({ version: 1, encryptionKey, signingKey })));

    const valid = fixture();
    const bundle = JSON.parse(valid.identityKey);
    assert.throws(() => parseDevicePublicBundle(JSON.stringify({
      ...bundle,
      encryptionKey: { ...bundle.encryptionKey, key_ops: [] },
    })));
    assert.throws(() => parseDevicePublicBundle(JSON.stringify({
      ...bundle,
      signingKey: { ...bundle.signingKey, ext: false },
    })));
  });

  it('canonicalizes browser key usage metadata and remains WebCrypto-importable', async () => {
    const valid = JSON.parse(fixture().identityKey);
    delete valid.encryptionKey.ext;
    delete valid.encryptionKey.key_ops;
    delete valid.signingKey.ext;
    delete valid.signingKey.key_ops;
    const canonical = JSON.parse(canonicalDeviceIdentityKey(JSON.stringify(valid)));
    assert.deepEqual(canonical.encryptionKey.key_ops, ['encrypt']);
    assert.deepEqual(canonical.signingKey.key_ops, ['verify']);
    assert.equal(canonical.encryptionKey.ext, true);
    assert.equal(canonical.signingKey.ext, true);
    await webcrypto.subtle.importKey('jwk', canonical.encryptionKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    await webcrypto.subtle.importKey('jwk', canonical.signingKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  });

  it('binds every wrapped channel key to one epoch commitment and recipient', () => {
    const keys = fixture();
    const envelope = {
      channelId: '00000000-0000-4000-8000-000000000001',
      keyVersion: 3,
      keyCommitment: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      recipientDeviceId: '00000000-0000-4000-8000-000000000002',
      encryptedKey: Buffer.alloc(256, 7).toString('base64'),
    };
    const signature = sign('sha256', Buffer.from(serializeChannelKeyWrap(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyChannelKeyWrapSignature(keys.identityKey, envelope, signature), true);
    assert.equal(verifyChannelKeyWrapSignature(keys.identityKey, { ...envelope, keyVersion: 4 }, signature), false);
    assert.equal(verifyChannelKeyWrapSignature(keys.identityKey, {
      ...envelope,
      recipientDeviceId: '00000000-0000-4000-8000-000000000099',
    }, signature), false);

    const acknowledgementEnvelope = {
      ...envelope,
      deliveryId: '00000000-0000-4000-8000-000000000003',
      distributorDeviceId: '00000000-0000-4000-8000-000000000004',
    };
    const acknowledgement = sign('sha256', Buffer.from(serializeChannelKeyAcknowledgement(acknowledgementEnvelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyChannelKeyAcknowledgementSignature(keys.identityKey, acknowledgementEnvelope, acknowledgement), true);
    assert.equal(verifyChannelKeyAcknowledgementSignature(
      keys.identityKey,
      { ...acknowledgementEnvelope, encryptedKey: Buffer.alloc(256, 8).toString('base64') },
      acknowledgement,
    ), false);
  });

  it('binds a provisional epoch abort to its channel, version, commitment, and device', () => {
    const keys = fixture();
    const envelope = {
      channelId: '00000000-0000-4000-8000-000000000001',
      keyVersion: 3,
      keyCommitment: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      deviceId: '00000000-0000-4000-8000-000000000002',
    };
    const signature = sign('sha256', Buffer.from(serializeChannelKeyEpochAbort(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyChannelKeyEpochAbortSignature(keys.identityKey, envelope, signature), true);
    assert.equal(verifyChannelKeyEpochAbortSignature(
      keys.identityKey,
      { ...envelope, keyVersion: 4 },
      signature,
    ), false);
  });
});

describe('attachment crypto protocol', () => {
  it('keeps attachment metadata signatures and AAD vectors stable', () => {
    const envelope: SignedAttachmentEnvelope = {
      type: 'attachment',
      uploadId: '00000000-0000-4000-8000-000000000001',
      messageId: '00000000-0000-4000-8000-000000000002',
      channelId: '00000000-0000-4000-8000-000000000003',
      authorId: '00000000-0000-4000-8000-000000000005',
      deviceId: '00000000-0000-4000-8000-000000000004',
      keyVersion: 7,
      filenameEnc: 'ZmlsZW5hbWU=',
      mimeType: 'application/octet-stream',
      wrappedKey: 'd3JhcHBlZA==',
      noncePrefix: 'BwcHBwcHBwc=',
      plaintextSize: 5_242_881,
      chunkCount: 2,
    };
    assert.equal(
      serializeAttachmentEnvelope(envelope),
      '[2,"attachment","00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002","00000000-0000-4000-8000-000000000003","00000000-0000-4000-8000-000000000005","00000000-0000-4000-8000-000000000004",7,"ZmlsZW5hbWU=","application/octet-stream","d3JhcHBlZA==","BwcHBwcHBwc=",5242881,2]',
    );
    assert.equal(
      serializeAttachmentFilenameAad(envelope.messageId),
      'alparts-attachment-filename-v1\0' + envelope.messageId,
    );
    assert.equal(
      serializeAttachmentWrappedKeyAad(envelope.messageId, envelope.uploadId),
      'alparts-attachment-file-key-v1\0' + envelope.messageId + '\0' + envelope.uploadId,
    );
    assert.equal(
      serializeAttachmentChunkAad(
        envelope.uploadId,
        envelope.messageId,
        1,
        envelope.chunkCount,
        envelope.plaintextSize,
      ),
      [
        'alparts-attachment-chunk-v1',
        envelope.uploadId,
        envelope.messageId,
        '1',
        '2',
        '5242881',
      ].join('\0'),
    );
    assert.equal(
      ATTACHMENT_CHUNK_AAD_FORMAT,
      'alparts-attachment-chunk-v1\\0{uploadId}\\0{messageId}\\0{index}\\0{chunkCount}\\0{plaintextSize}',
    );
  });

  it('changes the signed representation for every security-relevant field', () => {
    const envelope: SignedAttachmentEnvelope = {
      type: 'attachment',
      uploadId: '00000000-0000-4000-8000-000000000001',
      messageId: '00000000-0000-4000-8000-000000000002',
      channelId: '00000000-0000-4000-8000-000000000003',
      authorId: '00000000-0000-4000-8000-000000000005',
      deviceId: '00000000-0000-4000-8000-000000000004',
      keyVersion: 1,
      filenameEnc: 'ZmlsZW5hbWU=',
      mimeType: 'application/octet-stream',
      wrappedKey: 'd3JhcHBlZA==',
      noncePrefix: 'BwcHBwcHBwc=',
      plaintextSize: 1,
      chunkCount: 1,
    };
    const canonical = serializeAttachmentEnvelope(envelope);
    const mutations: SignedAttachmentEnvelope[] = [
      { ...envelope, uploadId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, messageId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, channelId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, authorId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, deviceId: '00000000-0000-4000-8000-000000000099' },
      { ...envelope, keyVersion: 2 },
      { ...envelope, filenameEnc: 'b3RoZXI=' },
      { ...envelope, mimeType: 'text/plain' },
      { ...envelope, wrappedKey: 'b3RoZXI=' },
      { ...envelope, noncePrefix: 'CAgICAgICAg=' },
      { ...envelope, plaintextSize: 2 },
      { ...envelope, chunkCount: 2 },
    ];
    for (const mutation of mutations) assert.notEqual(serializeAttachmentEnvelope(mutation), canonical);
  });

  it('verifies an uploader-device signature and rejects attachment metadata tampering', () => {
    const keys = fixture();
    const envelope: SignedAttachmentEnvelope = {
      type: 'attachment',
      uploadId: '00000000-0000-4000-8000-000000000001',
      messageId: '00000000-0000-4000-8000-000000000002',
      channelId: '00000000-0000-4000-8000-000000000003',
      authorId: '00000000-0000-4000-8000-000000000005',
      deviceId: '00000000-0000-4000-8000-000000000004',
      keyVersion: 1,
      filenameEnc: 'ZmlsZW5hbWU=',
      mimeType: 'application/octet-stream',
      wrappedKey: 'd3JhcHBlZA==',
      noncePrefix: 'BwcHBwcHBwc=',
      plaintextSize: 1,
      chunkCount: 1,
    };
    const signature = sign('sha256', Buffer.from(serializeAttachmentEnvelope(envelope)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal(verifyAttachmentEnvelopeSignature(keys.identityKey, envelope, signature), true);
    assert.equal(
      verifyAttachmentEnvelopeSignature(keys.identityKey, { ...envelope, wrappedKey: 'b3RoZXI=' }, signature),
      false,
    );
    assert.equal(
      verifyAttachmentEnvelopeSignature(keys.identityKey, envelope, Buffer.alloc(64).toString('base64')),
      false,
    );
  });
});
