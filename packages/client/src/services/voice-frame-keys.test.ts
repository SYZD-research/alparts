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
  /** Key messages the relay drops before it delivers again. */
  drop = 0;
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
    if (this.drop > 0) {
      this.drop -= 1;
      return false;
    }
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

  it('refuses a dropped key when it comes again, so frames recorded under it stay replays', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    const first = a.sendKey!;
    const recorded = (await a.frames.encrypt(new Uint8Array([1, 2, 3]).buffer))!;
    expect(await b.frames.decrypt(a.peer.participantId, recorded)).not.toBeNull();
    // Three newer keys of a: b drops the first.
    await call.join('c');
    await call.leave('c');
    await call.join('d');
    expect(b.installed.has(first.keyId)).toBe(false);
    // a sends its first key to b again, under a newer sequence number.
    const toB = call.relayed.map((message) => message.envelope).filter((envelope) => (
      envelope.senderParticipantId === a.peer.participantId && envelope.targetParticipantId === b.peer.participantId
    ));
    const again = { ...toB.find((envelope) => envelope.keyId === first.keyId)!, sequence: toB[toB.length - 1]!.sequence + 1 };
    expect(await b.keys.receive(again, `d-a:${serializeVoiceKeyEnvelope(again)}`)).toBe(false);
    expect(await b.frames.decrypt(a.peer.participantId, recorded)).toBeNull();
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

describe('call frame keys when key messages and other changes overlap', () => {
  const peer = (name: string): VoiceKeyPeer => ({ participantId: `p-${name}`, userId: `u-${name}`, deviceId: `d-${name}` });
  /** A key message to a; its wrapped key names it, so a test can hold its unwrapping. */
  const keyMessage = (sender: string, sequence: number, keyId: number): SignedVoiceKeyEnvelope => ({
    type: 'voice-key', sequence, channelId: CHANNEL,
    senderParticipantId: `p-${sender}`, senderDeviceId: `d-${sender}`,
    targetParticipantId: 'p-a', targetDeviceId: 'd-a',
    keyId, wrappedKey: btoa(`${sender} ${keyId}`.padEnd(120)),
  });
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

  /**
   * Participant a, in the call with `others` and sending under its key 1000.
   * A held step waits until the test finishes it; the log shows what reached
   * the frame transform.
   */
  async function inCall(...others: string[]) {
    const held = new Set<string>();
    const waiting = new Map<string, () => void>();
    const log: string[] = [];
    const step = (name: string) => (held.delete(name)
      ? new Promise<void>((resolve) => { waiting.set(name, resolve); })
      : Promise.resolve());
    let nextKeyId = 1000;
    const keys = new VoiceFrameKeys({ channelId: CHANNEL, ...peer('a') }, {
      randomKey: () => crypto.getRandomValues(new Uint8Array(32)),
      randomKeyId: () => nextKeyId++,
      identities: async (deviceIds) => new Map(deviceIds.map((deviceId) => [deviceId, { userId: `u-${deviceId.slice(2)}`, identityKey: deviceId }])),
      wrapKey: async () => 'A'.repeat(344),
      unwrapKey: async (wrapped) => {
        await step(`unwrap ${atob(wrapped).trim()}`);
        return new Uint8Array(32);
      },
      sign: async () => 'signature',
      verify: async () => true,
      send: async (envelope) => {
        await step(`ack ${envelope.targetParticipantId}`);
        return true;
      },
      useSendKey: async (keyId) => { log.push(`use ${keyId}`); },
      addReceiveKey: async (participantId, keyId) => {
        await step(`install ${keyId}`);
        log.push(`add ${participantId} ${keyId}`);
      },
      removeReceiveKey: (keyId) => { log.push(`remove ${keyId}`); },
      removeParticipant: (participantId) => { log.push(`forget ${participantId}`); },
      delay: () => step('delay'),
    });
    await keys.start(others.map(peer));
    log.length = 0;
    return {
      keys,
      log,
      /** Holds the next step of each name. */
      hold: (...names: string[]) => names.forEach((name) => held.add(name)),
      waiting: () => [...waiting.keys()],
      finish: async (name: string) => {
        const resume = waiting.get(name);
        if (!resume) throw new Error(`${name} is not waiting`);
        waiting.delete(name);
        resume();
        await settle();
      },
    };
  }

  it('installs the keys of others while its own new key still waits for the server and the switch', async () => {
    const a = await inCall('b');
    a.hold('ack p-b', 'ack p-c', 'delay');
    // c joins and everyone makes a new key. a's own waits until the server
    // relayed it, and then a moment longer before a sends under it.
    const joined = a.keys.participantJoined([peer('b'), peer('c')]);
    await settle();
    expect(a.waiting()).toEqual(['ack p-b', 'ack p-c']);
    const fromB = a.keys.receive(keyMessage('b', 1, 1), 'signature');
    await settle();
    expect(a.log).toEqual(['add p-b 1']);
    await a.finish('ack p-b');
    await a.finish('ack p-c');
    expect(a.waiting()).toEqual(['delay']);
    const fromC = a.keys.receive(keyMessage('c', 1, 2), 'signature');
    await settle();
    expect(a.log).toEqual(['add p-b 1', 'add p-c 2']);
    await a.finish('delay');
    await joined;
    expect([await fromB, await fromC]).toEqual([true, true]);
    expect(a.log).toEqual(['add p-b 1', 'add p-c 2', 'use 1001']);
  });

  it('installs the keys of one sender in the order they came, without holding up another sender', async () => {
    const a = await inCall('b', 'c');
    // b's first key is slow to install.
    a.hold('install 1');
    const fromB = Promise.all([1, 2, 3, 4].map((n) => a.keys.receive(keyMessage('b', n, n), 'signature')));
    const fromC = a.keys.receive(keyMessage('c', 1, 9), 'signature');
    await settle();
    expect(a.log).toEqual(['add p-c 9']);
    await a.finish('install 1');
    expect(await fromB).toEqual([true, true, true, true]);
    expect(await fromC).toBe(true);
    // b's oldest key goes once three newer ones are in, and does not come back.
    expect(a.log).toEqual(['add p-c 9', 'add p-b 1', 'add p-b 2', 'add p-b 3', 'add p-b 4', 'remove 1']);
  });

  it('refuses a key id that another key took while this one was unwrapped', async () => {
    const a = await inCall('b', 'c');
    // b and c send the same key id at once: only the first one unwrapped counts.
    a.hold('unwrap b 7', 'unwrap c 7');
    const fromB = a.keys.receive(keyMessage('b', 1, 7), 'signature');
    const fromC = a.keys.receive(keyMessage('c', 1, 7), 'signature');
    await settle();
    expect(a.waiting()).toEqual(['unwrap b 7', 'unwrap c 7']);
    await a.finish('unwrap b 7');
    await a.finish('unwrap c 7');
    expect([await fromB, await fromC]).toEqual([true, false]);
    // c sends the key id that a's own next key takes while c's is unwrapped.
    a.hold('unwrap c 1001');
    const taken = a.keys.receive(keyMessage('c', 2, 1001), 'signature');
    await settle();
    const joined = a.keys.participantJoined([peer('b'), peer('c'), peer('d')]);
    await settle();
    await a.finish('unwrap c 1001');
    await joined;
    expect(await taken).toBe(false);
    expect(a.log).toEqual(['add p-b 7', 'use 1001']);
  });

  it('keeps nothing of a key whose sender left while it was being installed', async () => {
    const a = await inCall('b', 'c');
    a.hold('install 1');
    const fromB = a.keys.receive(keyMessage('b', 1, 1), 'signature');
    await settle();
    const left = a.keys.participantLeft('p-b', [peer('c')]);
    await settle();
    await a.finish('install 1');
    await left;
    expect(await fromB).toBe(false);
    // b's key arrived after b's keys were removed, and is removed as well.
    expect(a.log).toEqual(['forget p-b', 'use 1001', 'add p-b 1', 'remove 1']);
    // Should b come back under the same id, its keys count from the start again.
    await a.keys.participantJoined([peer('b'), peer('c')]);
    expect(await a.keys.receive(keyMessage('b', 1, 2), 'signature')).toBe(true);
  });
});

describe('call frame keys when a key message is lost', () => {
  /** Lets the retries, which wait on a timer, run and deliver. */
  const retried = async (call: Call) => {
    for (let round = 0; round < 10; round += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      await call.settle();
    }
  };

  it('sends a new key to everyone again, so the participant that missed it hears the sender', async () => {
    const call = new Call();
    const a = await call.join('a');
    const b = await call.join('b');
    call.drop = 1;
    const c = await call.join('c');
    await retried(call);
    for (const sender of [a, b, c]) {
      for (const receiver of [a, b, c]) {
        if (sender !== receiver) expect(await sender.reaches(receiver)).toBe(true);
      }
    }
  });

  it('tries again only a few times while the relay keeps failing', async () => {
    const call = new Call();
    await call.join('a');
    await call.join('b');
    call.deliver = false;
    await call.join('c');
    await retried(call);
    const sent = call.relayed.length;
    await retried(call);
    expect(call.relayed.length).toBe(sent);
    // a: one key to b when b joined, then c's join and three retries, each to b and c.
    const fromA = call.relayed.filter((message) => message.envelope.senderParticipantId === 'p-a');
    expect(fromA).toHaveLength(1 + 2 * 4);
  });
});
