import { describe, expect, it } from 'vitest';
import type { Attachment, Message, SignedMessageEnvelope, User } from '@alparts/shared';
import {
  compareMessageEvents,
  getMessageCryptoVerificationState,
  hasAuthenticatedEnvelopeConflict,
  isMessageKeyUnavailable,
  markMessageCryptoVerification,
  markMessageKeyUnavailable,
  mergeMessageEvents,
  projectMessageEvents,
  retryMessageKeyVerification,
} from './message-projector';
import { channelSecurityError, matchesLocallySignedMessageResponse } from './message.store';

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
  return markMessageCryptoVerification({
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
  } as Message, true);
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

    const rawNewestFirst = [deletion, reaction, edit, second, original, wireEvent(edit, { content: '' })];
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
    const refreshed = wireEvent(stored, { content: '', reactions: [], isPinned: false });

    const [merged] = mergeMessageEvents([stored], [refreshed]);
    expect(merged).toMatchObject({ content: 'decrypted locally', reactions: [], isPinned: false });
  });

  it('ignores plaintext and a forged string verification marker from an exact wire duplicate', () => {
    const stored = event({
      id: '00000000-0000-4000-8000-000000000002',
      type: 'message',
      content: 'decrypted locally',
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    const wireDuplicate = {
      ...wireEvent(stored),
      content: 'server injected',
      cryptoVerified: true,
    } as Message & { cryptoVerified: boolean };

    const [merged] = mergeMessageEvents([stored], [wireDuplicate]);
    expect(merged.content).toBe('decrypted locally');
    expect(getMessageCryptoVerificationState(merged)).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(merged, 'cryptoVerified')).toBe(false);
  });

  it('quarantines one id that arrives with a different authenticated envelope', () => {
    const stored = event({
      id: '00000000-0000-4000-8000-000000000003',
      type: 'message',
      content: 'decrypted locally',
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    const conflictingDuplicate = {
      ...stored,
      encryptedContent: 'different-ciphertext',
      content: 'server injected',
    };

    const [merged] = mergeMessageEvents([stored], [conflictingDuplicate]);
    expect(merged.content).toBe('');
    expect(getMessageCryptoVerificationState(merged)).toBe(false);
    expect(hasAuthenticatedEnvelopeConflict(merged)).toBe(true);
    expect(projectMessageEvents([merged])[0].content).toBe('');
  });

  it('quarantines an old signed edit replayed under a new id instead of rolling the message back', () => {
    const base = event({ id: 'message-1', type: 'message', content: 'v0', createdAt: '2026-01-01T00:00:01.000Z' });
    const first = event({
      id: 'edit-1', type: 'edit', refMessageId: base.id, content: 'v1', idempotencyKey: 'edit-key-1',
      createdAt: '2026-01-01T00:00:02.000Z',
    });
    const second = event({
      id: 'edit-2', type: 'edit', refMessageId: base.id, content: 'v2', idempotencyKey: 'edit-key-2',
      createdAt: '2026-01-01T00:00:03.000Z',
    });
    const replay = { ...first, id: 'edit-3', createdAt: '2026-01-01T00:00:04.000Z' };

    const merged = mergeMessageEvents([base, first, second, replay]);
    expect(hasAuthenticatedEnvelopeConflict(merged.find((item) => item.id === 'edit-3')!)).toBe(true);
    expect(merged.filter(hasAuthenticatedEnvelopeConflict).map((item) => item.id)).toEqual(['edit-3']);
    expect(projectMessageEvents(merged)[0].content).toBe('v2');
    // The quarantine survives later merges, even without the original.
    const later = mergeMessageEvents(merged.filter((item) => item.id !== 'edit-1'), [event({ id: 'message-2', type: 'message', createdAt: '2026-01-01T00:00:05.000Z' })]);
    expect(hasAuthenticatedEnvelopeConflict(later.find((item) => item.id === 'edit-3')!)).toBe(true);
  });

  it('keeps the first time of an event when the server sends it again with a later one', () => {
    const base = event({ id: 'message-1', type: 'message', content: 'v0', createdAt: '2026-01-01T00:00:01.000Z' });
    const edit = event({
      id: 'edit-1', type: 'edit', refMessageId: base.id, content: 'v1', idempotencyKey: 'edit-key-1',
      createdAt: '2026-01-01T00:00:02.000Z',
    });
    const other = event({ id: 'message-2', type: 'message', content: 'next', createdAt: '2026-01-01T00:00:03.000Z' });
    const held = mergeMessageEvents([base, edit, other]);
    expect(projectMessageEvents(held).map((item) => item.content)).toEqual(['v1', 'next']);

    // The same base message, later in time, would otherwise drop its edit
    // (the edit would come before its target) and move the message down.
    const later = mergeMessageEvents(held, [{ ...base, createdAt: '2026-01-01T00:00:09.000Z' }]);
    expect(later.find((item) => item.id === base.id)!.createdAt).toBe(base.createdAt);
    expect(projectMessageEvents(later).map((item) => item.content)).toEqual(['v1', 'next']);
  });

  it('keeps a channel stopped while a quarantined copy is held, even after its error is cleared', () => {
    const original = event({ id: 'message-1', type: 'message', content: 'hello', idempotencyKey: 'send-key', createdAt: '2026-01-01T00:00:01.000Z' });
    const replay = { ...original, id: 'message-9', createdAt: '2026-01-01T00:00:09.000Z' };
    const held = mergeMessageEvents([original, replay]);
    // A later load of the same history clears the stored error.
    const state = { securityErrors: { 'channel-1': null }, eventsByChannel: { 'channel-1': held } };
    expect(channelSecurityError(state, 'channel-1')).toBeTruthy();
    expect(channelSecurityError({ ...state, eventsByChannel: { 'channel-1': [original] } }, 'channel-1')).toBeNull();
    expect(channelSecurityError({ securityErrors: { 'channel-1': 'other' }, eventsByChannel: {} }, 'channel-1')).toBe('other');
  });

  it('quarantines a copied message and ignores unverified events that reuse a key', () => {
    const original = event({ id: 'message-1', type: 'message', content: 'hello', idempotencyKey: 'send-key', createdAt: '2026-01-01T00:00:01.000Z' });
    const copy = { ...original, id: 'message-9', createdAt: '2026-01-01T00:00:09.000Z' };
    const merged = mergeMessageEvents([original, copy]);
    expect(merged.map((item) => hasAuthenticatedEnvelopeConflict(item))).toEqual([false, true]);
    expect(projectMessageEvents(merged).map((item) => item.content)).toEqual(['hello', '']);

    const forged = retryMessageKeyVerification({ ...original, id: 'message-0', createdAt: '2026-01-01T00:00:00.000Z' });
    const withForgery = mergeMessageEvents([forged, original]);
    expect(withForgery.some(hasAuthenticatedEnvelopeConflict)).toBe(false);
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

  it('keeps a missing-key result terminal until explicit reconciliation', () => {
    const unavailable = markMessageKeyUnavailable(wireEvent(event({
      id: '00000000-0000-4000-8000-000000000004',
      type: 'message',
      content: 'must not survive',
      createdAt: '2026-01-01T00:00:00.000Z',
    })));
    expect(isMessageKeyUnavailable(unavailable)).toBe(true);
    expect(getMessageCryptoVerificationState(unavailable)).toBe(false);
    expect(unavailable.content).toBe('');

    const [duplicate] = mergeMessageEvents([unavailable], [wireEvent(unavailable)]);
    expect(isMessageKeyUnavailable(duplicate)).toBe(true);
    expect(duplicate.content).toBe('');

    const retryable = retryMessageKeyVerification(duplicate);
    expect(isMessageKeyUnavailable(retryable)).toBe(false);
    expect(getMessageCryptoVerificationState(retryable)).toBeUndefined();
    expect(retryable.content).toBe('');
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
    const unsignedDelete = markMessageCryptoVerification({
      ...event({ id: 'delete-unverified', type: 'delete', refMessageId: original.id, createdAt: '2026-01-01T00:00:01.000Z' }),
      signature: null,
    } as Message, false);
    expect(projectMessageEvents([original, unsignedDelete])[0]).toMatchObject({ type: 'message', content: 'visible' });
  });

  it('does not render server-supplied base plaintext before verification', () => {
    const unverified = markMessageCryptoVerification({
      ...event({ id: 'message-unverified-base', type: 'message', content: 'server injected', createdAt: '2026-01-01T00:00:00.000Z' }),
    } as Message, false);
    expect(projectMessageEvents([unverified])[0].content).toBe('');
  });

  it('does not accept a network-supplied string verification property', () => {
    const forged = {
      ...wireEvent(event({
        id: 'message-forged-verification-marker',
        type: 'message',
        content: 'server injected',
        createdAt: '2026-01-01T00:00:00.000Z',
      })),
      cryptoVerified: true,
    } as Message & { cryptoVerified: boolean };
    expect(projectMessageEvents([forged])[0].content).toBe('');
  });
});

function wireEvent(message: Message, overrides: Partial<Message> = {}): Message {
  // JSON is the relevant trust boundary and cannot carry process-local Symbols.
  return { ...JSON.parse(JSON.stringify(message)) as Message, ...overrides };
}

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

  it('rejects a forum response that names a different post', () => {
    const forumExpected = { ...expected, postId: 'post-1' };
    expect(matchesLocallySignedMessageResponse({ ...response, postId: 'post-1' }, forumExpected, signature)).toBe(true);
    expect(matchesLocallySignedMessageResponse({ ...response, postId: 'post-2' }, forumExpected, signature)).toBe(false);
    expect(matchesLocallySignedMessageResponse({ ...response, postId: null }, forumExpected, signature)).toBe(false);
  });
});

describe('forum events in the projector', () => {
  it('treats one event id carrying two different posts as an equivocation', () => {
    const first = event({ id: 'reply', type: 'message', createdAt: '2026-01-01T00:00:00.000Z', postId: 'post-1', content: 'hello' });
    const moved = event({ id: 'reply', type: 'message', createdAt: '2026-01-01T00:00:00.000Z', postId: 'post-2', content: 'hello' });
    const [merged] = mergeMessageEvents([first], [moved]);
    expect(hasAuthenticatedEnvelopeConflict(merged)).toBe(true);
    expect(merged.content).toBe('');
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
