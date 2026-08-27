import { describe, expect, it } from 'vitest';
import type { Attachment, Message, SignedMessageEnvelope, User } from '@alparts/shared';
import { compareMessageEvents, mergeMessageEvents, projectMessageEvents } from './message-projector';
import { matchesLocallySignedMessageResponse } from './message.store';

const author: User = {
  id: 'user-1',
  email: 'alice@example.test',
  displayName: 'Alice',
  avatarUrl: null,
  status: 'online',
  createdAt: '2026-01-01T00:00:00.000Z',
};

function event(overrides: Partial<Message> & Pick<Message, 'id' | 'type' | 'createdAt'>): Message {
  const { id, type, createdAt, ...rest } = overrides;
  return {
    id,
    channelId: 'channel-1',
    authorId: overrides.authorId || author.id,
    author,
    deviceId: 'device-1',
    content: '',
    encryptedContent: 'ciphertext',
    contentNonce: 'nonce',
    keyVersion: 1,
    signature: 'signature',
    type,
    refMessageId: null,
    reactions: [],
    isPinned: false,
    idempotencyKey: `idem-${id}`,
    createdAt,
    ...rest,
    cryptoVerified: true,
  } as Message;
}

describe('projectMessageEvents', () => {
  it('uses binary UUID ordering for events with the same timestamp', () => {
    const timestamp = '2026-01-01T00:00:00.000Z';
    const lower = event({ id: '00000000-0000-0000-0000-000000000009', type: 'message', createdAt: timestamp });
    const higher = event({ id: '00000000-0000-0000-0000-00000000000a', type: 'message', createdAt: timestamp });

    expect(compareMessageEvents(lower, higher)).toBe(-1);
    expect(mergeMessageEvents([higher, lower]).map((item) => item.id)).toEqual([lower.id, higher.id]);
  });

  it('deduplicates newest-first pages and deterministically folds append-only events', () => {
    const original = event({
      id: 'message-1',
      type: 'message',
      content: 'before',
      createdAt: '2026-01-01T00:00:01.000Z',
    });
    const second = event({
      id: 'message-2',
      type: 'message',
      content: 'remove me',
      createdAt: '2026-01-01T00:00:02.000Z',
    });
    const edit = event({
      id: 'edit-1',
      type: 'edit',
      refMessageId: original.id,
      content: 'after',
      createdAt: '2026-01-01T00:00:03.000Z',
    });
    const reaction = event({
      id: 'reaction-1',
      type: 'reaction',
      refMessageId: original.id,
      authorId: 'user-2',
      content: '',
      encryptedContent: '👍',
      signature: null,
      createdAt: '2026-01-01T00:00:04.000Z',
    });
    const deletion = event({
      id: 'delete-1',
      type: 'delete',
      refMessageId: second.id,
      createdAt: '2026-01-01T00:00:05.000Z',
    });

    const rawNewestFirst = [deletion, reaction, edit, second, original, { ...edit, content: '' }];
    const merged = mergeMessageEvents(rawNewestFirst);
    const projected = projectMessageEvents(merged);

    expect(merged).toHaveLength(5);
    expect(projected.map((message) => message.id)).toEqual(['message-1', 'message-2']);
    expect(projected[0]).toMatchObject({ id: original.id, type: 'edit', content: 'after' });
    expect(projected[0].reactions).toEqual([{ emoji: '👍', count: 1, userIds: ['user-2'] }]);
    expect(projected[1]).toMatchObject({ id: second.id, type: 'delete', content: '' });
  });

  it('accepts authoritative removal of reaction and pin state without losing decrypted text', () => {
    const stored = event({
      id: '00000000-0000-4000-8000-000000000001',
      type: 'message',
      content: 'decrypted locally',
      reactions: [{ emoji: '👍', count: 1, userIds: ['user-1'] }],
      isPinned: true,
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    const refreshed = { ...stored, content: '', reactions: [], isPinned: false };

    const [merged] = mergeMessageEvents([stored], [refreshed]);
    expect(merged).toMatchObject({ content: 'decrypted locally', reactions: [], isPinned: false });
  });

  it('keeps immutable attachments when a duplicate socket event has an older empty snapshot', () => {
    const stored = event({
      id: '00000000-0000-4000-8000-000000000010',
      type: 'message',
      attachments: [attachment('00000000-0000-4000-8000-000000000020')],
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    const [merged] = mergeMessageEvents([stored], [{ ...stored, attachments: [] }]);
    expect(merged.attachments?.map((item) => item.id)).toEqual(['00000000-0000-4000-8000-000000000020']);
  });

  it('does not apply an edit signed by a different author', () => {
    const original = event({ id: 'message-author-bound', type: 'message', content: 'original', createdAt: '2026-01-01T00:00:00.000Z' });
    const attackerEdit = event({
      id: 'attacker-edit',
      type: 'edit',
      authorId: 'user-2',
      refMessageId: original.id,
      content: 'replaced',
      createdAt: '2026-01-01T00:00:01.000Z',
    });
    expect(projectMessageEvents([original, attackerEdit])[0].content).toBe('original');
  });

  it('does not apply mutation events before local signature verification', () => {
    const original = event({ id: 'message-verified-boundary', type: 'message', content: 'visible', createdAt: '2026-01-01T00:00:00.000Z' });
    const unsignedDelete = {
      ...event({ id: 'delete-unverified', type: 'delete', refMessageId: original.id, createdAt: '2026-01-01T00:00:01.000Z' }),
      cryptoVerified: false,
      signature: null,
    } as Message;
    expect(projectMessageEvents([original, unsignedDelete])[0]).toMatchObject({ type: 'message', content: 'visible' });
  });

  it('does not render server-supplied base plaintext before verification', () => {
    const unverified = {
      ...event({ id: 'message-unverified-base', type: 'message', content: 'server injected', createdAt: '2026-01-01T00:00:00.000Z' }),
      cryptoVerified: false,
    } as Message;
    expect(projectMessageEvents([unverified])[0].content).toBe('');
  });
});

describe('locally signed REST message responses', () => {
  const expected: SignedMessageEnvelope = {
    type: 'edit',
    channelId: 'channel-1',
    authorId: author.id,
    deviceId: 'device-1',
    keyVersion: 7,
    idempotencyKey: 'idem-edit-response',
    refMessageId: 'message-target',
    broadcastMention: false,
    encryptedContent: 'signed-ciphertext',
    contentNonce: 'signed-nonce',
  };
  const signature = 'signed-response';
  const response = event({
    id: 'edit-response',
    type: 'edit',
    channelId: expected.channelId,
    authorId: expected.authorId,
    deviceId: expected.deviceId,
    keyVersion: expected.keyVersion,
    idempotencyKey: expected.idempotencyKey,
    refMessageId: expected.refMessageId,
    broadcastMention: expected.broadcastMention,
    encryptedContent: expected.encryptedContent,
    contentNonce: expected.contentNonce,
    signature,
    createdAt: '2026-01-01T00:00:02.000Z',
  });

  it('accepts only the exact envelope and signature submitted by this device', () => {
    expect(matchesLocallySignedMessageResponse(response, expected, signature)).toBe(true);
  });

  it('rejects a server response redirected to another mutation target', () => {
    expect(matchesLocallySignedMessageResponse({
      ...response,
      refMessageId: 'different-message',
    }, expected, signature)).toBe(false);
    expect(matchesLocallySignedMessageResponse({
      ...response,
      signature: 'different-signature',
    }, expected, signature)).toBe(false);
    expect(matchesLocallySignedMessageResponse({
      ...response,
      author: { ...response.author, id: 'different-user' },
    }, expected, signature)).toBe(false);
  });
});

function attachment(id: string): Attachment {
  return {
    id,
    messageId: '00000000-0000-4000-8000-000000000010',
    channelId: 'channel-1',
    keyVersion: 1,
    deviceId: 'device-1',
    signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
    filenameEnc: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
    mimeType: 'text/plain',
    dangerousMime: false,
    downloadPolicy: 'attachment-only',
    sizeBytes: 17,
    ciphertextSizeBytes: 17,
    plaintextSizeBytes: 1,
    chunkCount: 1,
    wrappedKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    contentNonce: 'AAAAAAAAAAA=',
    cryptoManifest: {
      version: 1,
      algorithm: 'AES-256-GCM',
      nonceStrategy: 'prefix-counter-be32',
      noncePrefix: 'AAAAAAAAAAA=',
      aadVersion: 1,
      plaintextSize: 1,
      chunkPlaintextBytes: 5 * 1024 * 1024,
      authenticationTagBytes: 16,
      chunkCount: 1,
      uploadId: '00000000-0000-4000-8000-000000000030',
      messageId: '00000000-0000-4000-8000-000000000010',
      aadFormat: 'alparts-attachment-chunk-v1\\0{uploadId}\\0{messageId}\\0{index}\\0{chunkCount}\\0{plaintextSize}',
    },
    thumbnailKey: null,
    createdAt: '2026-01-01T00:00:01.000Z',
  };
}
