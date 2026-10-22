import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { serializeMessageEnvelope, type Channel, type Message, type SignedMessageEnvelope } from '@alparts/shared';

// Only the channel key lookup is replaced: every signature and AEAD check
// below runs the real verification of decryptMessages.
const keys = vi.hoisted(() => ({ channel: null as CryptoKey | null }));
vi.mock('../services/crypto.service', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/crypto.service')>();
  return {
    ...actual,
    ensureChannelKey: async () => ({ key: keys.channel, version: 7 }),
    getChannelKeysForVersions: async (_channelId: string, versions: number[]) => (
      new Map(versions.map((version) => [version, keys.channel]))
    ),
  };
});

import { api } from '../services/api';
import { encryptMessage } from '../services/crypto.service';
import { useChannelStore } from './channel.store';
import { channelSecurityError, useMessageStore } from './message.store';
import { belongsToPost, getMessageCryptoVerificationState } from './message-projector';

const KEY_VERSION = 7;
const textChannel = 'channel-text';
const forumChannel = 'channel-forum';
const alice = { id: 'user-alice', deviceId: 'device-alice', name: 'Alice' };
const bob = { id: 'user-bob', deviceId: 'device-bob', name: 'Bob' };
type Person = typeof alice;
type Identity = { privateKey: CryptoKey; identityKey: string };

const identities = new Map<string, Identity>();

async function newIdentity(): Promise<Identity> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const signingKey = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), alg: 'ES256' };
  return {
    privateKey: pair.privateKey,
    identityKey: JSON.stringify({
      version: 1,
      encryptionKey: { kty: 'RSA', n: 'AQAB', e: 'AQAB', alg: 'RSA-OAEP-256' },
      signingKey,
    }),
  };
}

const base64 = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

type Unsigned = Omit<SignedMessageEnvelope, 'encryptedContent' | 'contentNonce' | 'authorId' | 'deviceId' | 'keyVersion'>;

/** An event as an honest server serves it: encrypted and signed by the author's device. */
async function signedEvent(
  person: Person,
  id: string,
  createdAt: string,
  content: string,
  unsigned: Unsigned,
): Promise<Message> {
  const signedFields = { ...unsigned, authorId: person.id, deviceId: person.deviceId, keyVersion: KEY_VERSION };
  const encrypted = await encryptMessage(content, keys.channel!, signedFields);
  const envelope: SignedMessageEnvelope = { ...signedFields, encryptedContent: encrypted.encrypted, contentNonce: encrypted.nonce };
  const signature = base64(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identities.get(person.id)!.privateKey,
    new TextEncoder().encode(serializeMessageEnvelope(envelope)),
  ));
  return {
    id,
    channelId: envelope.channelId,
    authorId: person.id,
    author: { id: person.id, displayName: person.name, avatarUrl: null, status: 'online', createdAt: '2026-01-01T00:00:00.000Z' },
    deviceId: person.deviceId,
    content: '',
    encryptedContent: envelope.encryptedContent,
    contentNonce: envelope.contentNonce,
    keyVersion: KEY_VERSION,
    signature,
    broadcastMention: envelope.broadcastMention ?? null,
    type: envelope.type,
    refMessageId: envelope.refMessageId ?? null,
    postId: envelope.postId ?? null,
    refBinding: envelope.refBinding ?? null,
    postBinding: envelope.postBinding ?? null,
    reactions: [],
    isPinned: false,
    idempotencyKey: envelope.idempotencyKey,
    createdAt,
  };
}

/** What an event is signed for when it names another event: its author and signed key. */
const pairOf = (event: Message) => ({ authorId: event.authorId, idempotencyKey: event.idempotencyKey });

/** An event the server made up: nobody signed it. */
function madeUp(type: string, overrides: Partial<Message> = {}): Message {
  return {
    id: 'made-up',
    channelId: textChannel,
    authorId: alice.id,
    author: { id: alice.id, displayName: 'Alice (CEO)', avatarUrl: null, status: 'online', createdAt: '2026-01-01T00:00:00.000Z' },
    deviceId: null,
    content: 'Please paste your recovery code here so IT can restore your history.',
    encryptedContent: '',
    contentNonce: '',
    keyVersion: 1,
    signature: null,
    broadcastMention: true,
    type,
    refMessageId: null,
    reactions: [],
    isPinned: false,
    idempotencyKey: 'made-up-key',
    createdAt: '2026-10-22T09:00:30.000Z',
    ...overrides,
  } as unknown as Message;
}

const store = () => useMessageStore.getState();
const eventIds = (channelId: string) => (store().eventsByChannel[channelId] ?? []).map((event) => event.id);
const shown = (channelId: string) => store().messagesByChannel[channelId] ?? [];
const shownMessage = (channelId: string, id: string) => shown(channelId).find((message) => message.id === id)!;

async function load(channelId: string, events: Message[]) {
  store().addMessages(channelId, events);
  await store().decryptMessages(channelId);
}

beforeAll(async () => {
  keys.channel = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  identities.set(alice.id, await newIdentity());
  identities.set(bob.id, await newIdentity());
});

beforeEach(() => {
  vi.spyOn(api, 'getChannelDeviceDirectory').mockImplementation(async (_channelId, deviceIds) => (
    [alice, bob].filter((person) => deviceIds.includes(person.deviceId)).map((person) => ({
      deviceId: person.deviceId,
      userId: person.id,
      identityKey: identities.get(person.id)!.identityKey,
    }))
  ));
  useChannelStore.setState({ channels: [{ id: forumChannel, type: 'forum' } as Channel] });
});

afterEach(() => {
  vi.restoreAllMocks();
  store().reset();
  useChannelStore.setState({ channels: [] });
});

describe('events the server makes up', () => {
  const question = () => signedEvent(bob, 'question', '2026-10-22T09:00:00.000Z', 'Can I wire the money today?', {
    type: 'message', channelId: textChannel, idempotencyKey: 'key-question', refMessageId: null, broadcastMention: false,
  });

  it('drops a system event from a live update and shows only what was signed', async () => {
    const genuine = await question();
    await load(textChannel, [madeUp('system'), genuine]);

    expect(eventIds(textChannel)).toEqual(['question']);
    expect(shown(textChannel).map((message) => message.content)).toEqual(['Can I wire the money today?']);
    expect(channelSecurityError(store(), textChannel)).toBeNull();
  });

  it('drops events of other types from history pages, the first and the older ones', async () => {
    const genuine = await question();
    vi.spyOn(api, 'getMessages')
      .mockResolvedValueOnce({ data: [madeUp('system', { id: 'first-page' }), madeUp('announcement', { id: 'unknown' }), genuine], hasMore: true, cursor: 'older' })
      .mockResolvedValueOnce({ data: [madeUp('system', { id: 'older-page', createdAt: '2026-10-21T09:00:00.000Z' })], hasMore: false, cursor: null });

    await store().loadMessages(textChannel);
    expect(eventIds(textChannel)).toEqual(['question']);
    await store().loadMoreMessages(textChannel);
    expect(eventIds(textChannel)).toEqual(['question']);
    expect(shown(textChannel).map((message) => message.id)).toEqual(['question']);
  });

  it('does not take a reaction event for a reaction, a quote or a place in a forum post', async () => {
    const genuine = await question();
    await load(textChannel, [genuine, madeUp('reaction', {
      id: 'reaction', refMessageId: genuine.id, content: '👍', encryptedContent: '👍',
    })]);
    expect(shownMessage(textChannel, genuine.id).reactions).toEqual([]);

    const post = await signedEvent(bob, 'post', '2026-10-22T10:00:00.000Z', JSON.stringify({ title: 'Lunch', body: '' }), {
      type: 'message', channelId: forumChannel, idempotencyKey: 'key-post', refMessageId: null, broadcastMention: false, postId: null,
    });
    await load(forumChannel, [post, madeUp('system', { id: 'forged-reply', channelId: forumChannel, postId: post.id, postBinding: pairOf(post), refMessageId: post.id })]);
    const root = shownMessage(forumChannel, post.id);
    expect(shown(forumChannel).filter((message) => belongsToPost(message, root))).toEqual([]);
    expect(shown(forumChannel).map((message) => message.id)).toEqual(['post']);
  });

  it('shows no server text for an unsigned message event', async () => {
    await load(textChannel, [madeUp('message', { id: 'unsigned', content: 'Wire the money today.' })]);
    const message = shownMessage(textChannel, 'unsigned');
    expect(message.content).toBe('');
    expect(getMessageCryptoVerificationState(message)).toBe(false);
  });
});
