import { describe, expect, it } from 'vitest';
import type { SignedVoiceKeyEnvelope } from '@alparts/shared';
import { serializeVoiceKeyEnvelope } from '@alparts/shared';
import { VoiceFrameKeys, type VoiceKeyPeer } from './voice-frame-keys';
import { VoiceFrameCrypto } from './voice-frame-transform';
import { deriveSFrameKey } from './sframe';

const CHANNEL = '00000000-0000-4000-8000-0000000000c1';

/**
 * A call between in-memory clients. Wrapping and signing are modelled by
 * tagging the key with its recipient device and the envelope with its signer;
 * the relay is the server, which tests can make drop or replay messages.
 */
class Call {
  readonly clients = new Map<string, Client>();
  readonly relayed: Array<{ envelope: SignedVoiceKeyEnvelope; signature: string }> = [];
  deliver = true;
  private nextKeyId = 1;

  keyId(): number {
    return this.nextKeyId++;
  }

  peers(): VoiceKeyPeer[] {
    return [...this.clients.values()].map((client) => client.peer);
  }

  async join(name: string): Promise<Client> {
    const client = new Client(this, name);
    this.clients.set(name, client);
    const everyone = this.peers();
    await Promise.all([
      client.keys.start(everyone),
      ...[...this.clients.values()].filter((other) => other !== client).map((other) => other.keys.participantJoined(everyone)),
    ]);
    await this.settle();
    return client;
  }

  async leave(name: string): Promise<void> {
    const client = this.clients.get(name)!;
    client.keys.close();
    this.clients.delete(name);
    const everyone = this.peers();
    await Promise.all([...this.clients.values()].map((other) => other.keys.participantLeft(client.peer.participantId, everyone)));
    await this.settle();
  }

  async send(envelope: SignedVoiceKeyEnvelope, signature: string): Promise<boolean> {
    this.relayed.push({ envelope, signature });
    if (!this.deliver) return false;
    const target = [...this.clients.values()].find((client) => client.peer.participantId === envelope.targetParticipantId);
    if (!target) return false;
    target.inbox.push(target.keys.receive(envelope, signature));
    return true;
  }

  async settle(): Promise<void> {
    for (let round = 0; round < 5; round += 1) {
      await Promise.all([...this.clients.values()].flatMap((client) => client.inbox.splice(0)));
    }
  }
}

class Client {
  readonly peer: VoiceKeyPeer;
  readonly inbox: Array<Promise<boolean>> = [];
  readonly frames = new VoiceFrameCrypto();
  readonly keys: VoiceFrameKeys;
  /** Raw keys this client installed, by key id (to compare across clients). */
  readonly installed = new Map<number, { participantId: string; key: string }>();
  sendKey: { keyId: number; key: string } | null = null;

  constructor(call: Call, readonly name: string) {
    this.peer = { participantId: `p-${name}`, userId: `u-${name}`, deviceId: `d-${name}` };
    const self = { channelId: CHANNEL, ...this.peer };
    this.keys = new VoiceFrameKeys(self, {
      randomKey: () => crypto.getRandomValues(new Uint8Array(32)),
      randomKeyId: () => call.keyId(),
      identities: async (deviceIds) => new Map(deviceIds.map((deviceId) => [deviceId, {
        userId: `u-${deviceId.slice(2)}`,
        identityKey: `identity-${deviceId}`,
      }])),
      wrapKey: async (key, identityKey) => btoa(`${identityKey}|${[...key].join(',')}|`.padEnd(120, '.')),
      unwrapKey: async (wrapped) => {
        const [recipient, bytes] = atob(wrapped).split('|');
        if (recipient !== `identity-${this.peer.deviceId}`) throw new Error('not for this device');
        return Uint8Array.from(bytes!.split(',').map(Number));
      },
      sign: async (envelope) => `${envelope.senderDeviceId}:${serializeVoiceKeyEnvelope(envelope)}`,
      verify: async (envelope, signature, identityKey) => (
        identityKey === `identity-${envelope.senderDeviceId}` && signature === `${envelope.senderDeviceId}:${serializeVoiceKeyEnvelope(envelope)}`
      ),
      send: (envelope, signature) => call.send(envelope, signature),
      useSendKey: async (keyId, key) => {
        this.sendKey = { keyId, key: key.join(',') };
        const derived = await deriveSFrameKey(key, BigInt(keyId));
        this.frames.handle({ type: 'send-key', keyId, key: derived.key, salt: derived.salt });
      },
      addReceiveKey: async (participantId, keyId, key) => {
        this.installed.set(keyId, { participantId, key: key.join(',') });
        const derived = await deriveSFrameKey(key, BigInt(keyId));
        this.frames.handle({ type: 'receive-key', participantId, keyId, key: derived.key, salt: derived.salt });
      },
      removeReceiveKey: (keyId) => {
        this.installed.delete(keyId);
        this.frames.handle({ type: 'remove-key', keyId });
      },
      removeParticipant: (participantId) => {
        for (const [keyId, entry] of this.installed) if (entry.participantId === participantId) this.installed.delete(keyId);
        this.frames.handle({ type: 'remove-participant', participantId });
      },
      delay: async () => undefined,
    });
  }

  /** Whether `receiver` can read a frame this client sends now. */
  async reaches(receiver: Client): Promise<boolean> {
    const frame = await this.frames.encrypt(new TextEncoder().encode(`audio from ${this.name}`).buffer);
    if (!frame) return false;
    const plaintext = await receiver.frames.decrypt(this.peer.participantId, frame);
    return plaintext !== null && new TextDecoder().decode(plaintext) === `audio from ${this.name}`;
  }
}

describe('call frame keys (formal model M8k)', () => {
  it('lets every participant read every other participant once keys are exchanged', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const c = await call.join('c');
    for (const sender of [a, b, c]) {
      for (const receiver of [a, b, c]) {
        if (sender !== receiver) expect(await sender.reaches(receiver)).toBe(true);
      }
    }
  });

  it('never gives a newcomer a key used before it joined', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const before = a.sendKey!.key;
    const c = await call.join('c');
    expect(a.sendKey!.key).not.toBe(before);
    expect([...c.installed.values()].map((entry) => entry.key)).not.toContain(before);
    expect(await a.reaches(b)).toBe(true);
    expect(await a.reaches(c)).toBe(true);
  });

  it('never gives a former participant a key used after it left', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const c = await call.join('c');
    const heldByC = new Set([...c.installed.values()].map((entry) => entry.key));
    await call.leave('c');
    expect(heldByC.has(a.sendKey!.key)).toBe(false);
    expect(heldByC.has(b.sendKey!.key)).toBe(false);
    expect(await a.reaches(c)).toBe(false);
    expect(await a.reaches(b)).toBe(true);
    expect(await b.reaches(a)).toBe(true);
  });

  it('refuses replayed, misaddressed and forged key messages', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const toB = call.relayed.filter((message) => message.envelope.targetParticipantId === b.peer.participantId);
    const latest = toB[toB.length - 1]!;
    // The same message again.
    expect(await b.keys.receive(latest.envelope, latest.signature)).toBe(false);
    // Addressed to another participant or device.
    expect(await a.keys.receive(latest.envelope, latest.signature)).toBe(false);
    const misaddressed = { ...latest.envelope, sequence: latest.envelope.sequence + 1, targetDeviceId: 'd-x' };
    expect(await b.keys.receive(misaddressed, `d-a:${serializeVoiceKeyEnvelope(misaddressed)}`)).toBe(false);
    // Signed by another device than the participant's.
    const forged = { ...latest.envelope, sequence: latest.envelope.sequence + 1, senderDeviceId: 'd-b' };
    expect(await b.keys.receive(forged, `d-b:${serializeVoiceKeyEnvelope(forged)}`)).toBe(false);
    // A changed field breaks the signature.
    const changed = { ...latest.envelope, sequence: latest.envelope.sequence + 1, keyId: 999 };
    expect(await b.keys.receive(changed, latest.signature)).toBe(false);
    // A key id that names another participant's key.
    const bKeyId = b.sendKey!.keyId;
    const squat = { ...latest.envelope, sequence: latest.envelope.sequence + 1, keyId: bKeyId };
    expect(await b.keys.receive(squat, `d-a:${serializeVoiceKeyEnvelope(squat)}`)).toBe(false);
    expect(await a.reaches(b)).toBe(true);
  });

  it('refuses keys from someone who is not in the call', async () => {
    const call = new Call();
    const a = await call.join('a');
    const outsider: SignedVoiceKeyEnvelope = {
      type: 'voice-key', sequence: 1, channelId: CHANNEL,
      senderParticipantId: 'p-z', senderDeviceId: 'd-z',
      targetParticipantId: a.peer.participantId, targetDeviceId: a.peer.deviceId,
      keyId: 77, wrappedKey: btoa(`identity-d-a|${Array.from({ length: 32 }, () => 1).join(',')}|`.padEnd(120, '.')),
    };
    expect(await a.keys.receive(outsider, `d-z:${serializeVoiceKeyEnvelope(outsider)}`)).toBe(false);
  });

  it('sends nothing until it has its own key, and nothing a receiver cannot attribute', async () => {
    const frames = new VoiceFrameCrypto();
    expect(await frames.encrypt(new Uint8Array(10).buffer)).toBeNull();
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const frame = (await a.frames.encrypt(new Uint8Array([1, 2, 3]).buffer))!;
    // A's frame served as if it came from someone else is dropped.
    expect(await b.frames.decrypt('p-z', frame)).toBeNull();
    expect(await b.frames.decrypt(a.peer.participantId, frame)).not.toBeNull();
    // The same frame again is a replay.
    expect(await b.frames.decrypt(a.peer.participantId, frame)).toBeNull();
    // A plaintext frame is never passed on.
    expect(await b.frames.decrypt(a.peer.participantId, new Uint8Array(40).buffer)).toBeNull();
  });
});

describe('call frame keys when someone leaves during a rotation', () => {
  it('neither sends nor uses a key for someone who left while it was being sent', async () => {
    const self = { channelId: CHANNEL, participantId: 'p-a', userId: 'u-a', deviceId: 'd-a' };
    const peer = (name: string): VoiceKeyPeer => ({ participantId: `p-${name}`, userId: `u-${name}`, deviceId: `d-${name}` });
    const sent: Array<{ target: string; keyId: number }> = [];
    const used: number[] = [];
    const signatures: Array<() => void> = [];
    let nextKeyId = 1;
    const keys = new VoiceFrameKeys(self, {
      randomKey: () => crypto.getRandomValues(new Uint8Array(32)),
      randomKeyId: () => nextKeyId++,
      identities: async (deviceIds) => new Map(deviceIds.map((deviceId) => [deviceId, { userId: `u-${deviceId.slice(2)}`, identityKey: deviceId }])),
      wrapKey: async () => 'A'.repeat(344),
      unwrapKey: async () => new Uint8Array(32),
      // Signing waits until the test lets it finish.
      sign: () => new Promise<string>((resolve) => { signatures.push(() => resolve('signature')); }),
      verify: async () => true,
      send: async (envelope) => { sent.push({ target: envelope.targetParticipantId, keyId: envelope.keyId }); return true; },
      useSendKey: async (keyId) => { used.push(keyId); },
      addReceiveKey: async () => undefined,
      removeReceiveKey: () => undefined,
      removeParticipant: () => undefined,
      delay: async () => undefined,
    });
    const settle = async () => { for (let round = 0; round < 10; round += 1) await Promise.resolve(); };
    const joined = keys.participantJoined([peer('b'), peer('c')]);
    await settle();
    expect(signatures).toHaveLength(2);
    // c leaves while a is signing key 1 for b and c.
    const left = keys.participantLeft('p-c', [peer('b')]);
    signatures.splice(0).forEach((finish) => finish());
    await joined;
    await settle();
    // The leave's rotation signs key 2 for b only.
    expect(signatures).toHaveLength(1);
    signatures.splice(0).forEach((finish) => finish());
    await left;
    expect(sent).toEqual([{ target: 'p-b', keyId: 1 }, { target: 'p-b', keyId: 2 }]);
    // Key 1 was meant for c as well, so it is never used.
    expect(used).toEqual([2]);
    expect(keys.currentKeyId).toBe(2);
  });
});
