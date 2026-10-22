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
import { belongsToPost, getMessageCryptoVerificationState, quotedMessage } from './message-projector';

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

describe('a message that failed verification in a text channel', () => {
  const question = () => signedEvent(bob, 'question', '2026-10-22T09:00:00.000Z', 'Can I wire the money today?', {
    type: 'message', channelId: textChannel, idempotencyKey: 'key-question', refMessageId: null, broadcastMention: false,
  });
  const lunch = () => signedEvent(alice, 'lunch', '2026-10-22T09:01:00.000Z', 'Lunch at 12?', {
    type: 'message', channelId: textChannel, idempotencyKey: 'key-lunch', refMessageId: null, broadcastMention: false,
  });
  const editOfLunch = (lunchEvent: Message) => signedEvent(alice, 'lunch-edit', '2026-10-22T09:02:00.000Z', 'Yes, approved.', {
    type: 'edit', channelId: textChannel, idempotencyKey: 'key-lunch-edit', refMessageId: lunchEvent.id, broadcastMention: false,
    refBinding: pairOf(lunchEvent),
  });
  /** The server serves Alice's message as if it answered Bob's question. */
  const moved = (lunchEvent: Message, questionEvent: Message) => (
    { ...lunchEvent, refMessageId: questionEvent.id, refBinding: pairOf(questionEvent) } as Message
  );

  it('keeps the text of the author edit off a message the server moved under a quote', async () => {
    const [asked, original] = await Promise.all([question(), lunch()]);
    const tampered = moved(original, asked);
    await load(textChannel, [asked, tampered, await editOfLunch(original)]);

    const events = store().eventsByChannel[textChannel];
    expect(getMessageCryptoVerificationState(events.find((event) => event.id === asked.id)!)).toBe(true);
    expect(getMessageCryptoVerificationState(events.find((event) => event.id === 'lunch-edit')!)).toBe(true);
    const message = shownMessage(textChannel, 'lunch');
    expect(getMessageCryptoVerificationState(message)).toBe(false);
    expect(message).toMatchObject({ type: 'message', content: '' });
    expect(quotedMessage(message, shown(textChannel))).toBeNull();
    expect(channelSecurityError(store(), textChannel)).toBeNull();
  });

  it('does not show the quote the server chose even before any edit', async () => {
    const [asked, original] = await Promise.all([question(), lunch()]);
    await load(textChannel, [asked, moved(original, asked)]);
    const message = shownMessage(textChannel, 'lunch');
    expect(message.content).toBe('');
    expect(quotedMessage(message, shown(textChannel))).toBeNull();
  });

  it('still shows a verified quote and the verified edit of it', async () => {
    const asked = await question();
    const quote = await signedEvent(alice, 'answer', '2026-10-22T09:01:00.000Z', 'Let me check.', {
      type: 'message', channelId: textChannel, idempotencyKey: 'key-answer', refMessageId: asked.id, broadcastMention: false,
      refBinding: pairOf(asked),
    });
    const edit = await signedEvent(alice, 'answer-edit', '2026-10-22T09:02:00.000Z', 'Yes, approved.', {
      type: 'edit', channelId: textChannel, idempotencyKey: 'key-answer-edit', refMessageId: quote.id, broadcastMention: false,
      refBinding: pairOf(quote),
    });
    await load(textChannel, [asked, quote, edit]);

    const message = shownMessage(textChannel, 'answer');
    expect(message).toMatchObject({ type: 'edit', content: 'Yes, approved.' });
    expect(getMessageCryptoVerificationState(message)).toBe(true);
    expect(quotedMessage(message, shown(textChannel))?.id).toBe(asked.id);
  });

  it('still applies a verified edit to a verified message without references', async () => {
    const original = await lunch();
    await load(textChannel, [original, await editOfLunch(original)]);
    expect(shownMessage(textChannel, 'lunch')).toMatchObject({ type: 'edit', content: 'Yes, approved.' });
  });
});

describe('a reply that failed verification in a forum', () => {
  const forumPost = (id: string, key: string, createdAt: string, title: string) => signedEvent(bob, id, createdAt, JSON.stringify({ title, body: '' }), {
    type: 'message', channelId: forumChannel, idempotencyKey: key, refMessageId: null, broadcastMention: false, postId: null,
  });
  const reply = (post: Message) => signedEvent(alice, 'reply', '2026-10-22T10:02:00.000Z', 'the usual place', {
    type: 'message', channelId: forumChannel, idempotencyKey: 'key-reply', refMessageId: null, broadcastMention: false,
    postId: post.id, refBinding: null, postBinding: pairOf(post),
  });
  const editOfReply = (post: Message, replyEvent: Message) => signedEvent(alice, 'reply-edit', '2026-10-22T10:03:00.000Z', 'I fully agree.', {
    type: 'edit', channelId: forumChannel, idempotencyKey: 'key-reply-edit', refMessageId: replyEvent.id, broadcastMention: false,
    postId: post.id, refBinding: pairOf(replyEvent), postBinding: pairOf(post),
  });
  const repliesOf = (postId: string) => {
    const root = shownMessage(forumChannel, postId);
    return shown(forumChannel).filter((message) => belongsToPost(message, root)).map((message) => `${message.author.displayName}: ${message.content}`);
  };

  it('lists a verified reply and its verified edit under the post it was signed for', async () => {
    const lunchPost = await forumPost('post-lunch', 'key-lunch', '2026-10-22T10:00:00.000Z', 'Team lunch');
    const layoffPost = await forumPost('post-layoffs', 'key-layoffs', '2026-10-22T10:01:00.000Z', 'Layoffs: who agrees?');
    const original = await reply(lunchPost);
    await load(forumChannel, [lunchPost, layoffPost, original, await editOfReply(lunchPost, original)]);

    expect(repliesOf('post-lunch')).toEqual(['Alice: I fully agree.']);
    expect(repliesOf('post-layoffs')).toEqual([]);
  });

  it('lists neither a reply the server moved to another post nor the edit of it', async () => {
    const lunchPost = await forumPost('post-lunch', 'key-lunch', '2026-10-22T10:00:00.000Z', 'Team lunch');
    const layoffPost = await forumPost('post-layoffs', 'key-layoffs', '2026-10-22T10:01:00.000Z', 'Layoffs: who agrees?');
    const original = await reply(lunchPost);
    const edit = await editOfReply(lunchPost, original);
    const moved = { ...original, postId: layoffPost.id, postBinding: pairOf(layoffPost) } as Message;
    await load(forumChannel, [lunchPost, layoffPost, moved, edit]);

    expect(getMessageCryptoVerificationState(shownMessage(forumChannel, 'reply'))).toBe(false);
    expect(shownMessage(forumChannel, 'reply')).toMatchObject({ type: 'message', content: '' });
    expect(repliesOf('post-layoffs')).toEqual([]);
    expect(repliesOf('post-lunch')).toEqual([]);
  });
});
