import type { SignedVoiceKeyEnvelope } from '@alparts/shared';

/**
 * Frame keys of one SFU call (formal model M8k).
 *
 * Every participant encrypts its frames under its own key and sends that key
 * to each other participant, wrapped for the recipient device and signed by
 * its own device. It replaces its key whenever someone joins (so a newcomer
 * cannot read earlier frames) or leaves (so a former participant cannot read
 * later ones). After a join it starts sending under the new key a moment
 * after the server relayed it, so the others can install it first; after a
 * leave, at once. A key that reached someone who has left by then is never
 * used: the rotation that leave queued replaces it.
 */
export interface VoiceKeyPeer {
  participantId: string;
  userId: string;
  deviceId: string;
}

export interface VoiceKeyIdentity {
  userId: string;
  identityKey: string;
}

export interface VoiceFrameKeyDependencies {
  /** A new random base key (32 bytes). */
  randomKey(): Uint8Array;
  /** A new random key id below 2^32. */
  randomKeyId(): number;
  /** Device directory entries of these devices (cached by the caller). */
  identities(deviceIds: string[]): Promise<Map<string, VoiceKeyIdentity>>;
  wrapKey(key: Uint8Array, recipientIdentityKey: string): Promise<string>;
  unwrapKey(wrappedKey: string): Promise<Uint8Array>;
  sign(envelope: SignedVoiceKeyEnvelope): Promise<string>;
  verify(envelope: SignedVoiceKeyEnvelope, signature: string, identityKey: string): Promise<boolean>;
  /** Relay through the server; true when the server delivered it to the target. */
  send(envelope: SignedVoiceKeyEnvelope, signature: string): Promise<boolean>;
  /** Install keys in the frame transform. */
  useSendKey(keyId: number, key: Uint8Array): Promise<void>;
  addReceiveKey(participantId: string, keyId: number, key: Uint8Array): Promise<void>;
  removeReceiveKey(keyId: number): void;
  removeParticipant(participantId: string): void;
  /** Wait before sending under a new key, so receivers can install it first. */
  delay(ms: number): Promise<void>;
}

export interface VoiceFrameKeySelf {
  channelId: string;
  participantId: string;
  userId: string;
  deviceId: string;
}

const KEY_BYTES = 32;
const MAX_KEY_ID = 0xffff_ffff;
/** Keys of one sender a receiver keeps: the newest and the ones before it, for frames still in flight. */
const RECEIVE_KEYS_PER_SENDER = 3;
const SWITCH_DELAY_MS = 250;
/** Key messages from someone not yet known to be in the call, kept until it is (or dropped, oldest first). */
const MAX_EARLY_MESSAGES = 16;
const WRAPPED_KEY = /^[A-Za-z0-9+/]{100,1400}={0,2}$/;

interface InboundState {
  deviceId: string;
  lastSequence: number;
  keyIds: number[];
}

export class VoiceFrameKeys {
  private participants = new Map<string, VoiceKeyPeer>();
  private readonly outboundSequences = new Map<string, number>();
  private readonly inbound = new Map<string, InboundState>();
  /** Every key id seen in this call and its owner; a key id names one key of one participant. */
  private readonly keyOwners = new Map<number, string>();
  private readonly ownKeyIds = new Set<number>();
  private queue: Promise<void> = Promise.resolve();
  private readonly early: Array<{ envelope: SignedVoiceKeyEnvelope; signature: string }> = [];
  private closed = false;
  /** The key frames are sent under, once installed. */
  currentKeyId: number | null = null;

  constructor(
    private readonly self: VoiceFrameKeySelf,
    private readonly deps: VoiceFrameKeyDependencies,
  ) {}

  /** Join: create a first key and send it to everyone already in the call. */
  start(participants: VoiceKeyPeer[]): Promise<void> {
    this.setParticipants(participants);
    return this.rotate('start');
  }

  /** Someone joined: a new key, sent to everyone including the newcomer. */
  participantJoined(participants: VoiceKeyPeer[]): Promise<void> {
    this.setParticipants(participants);
    return this.rotate('join');
  }

  /** Someone left: forget its keys and send a new key to the others. */
  participantLeft(participantId: string, participants: VoiceKeyPeer[]): Promise<void> {
    this.forget(participantId);
    this.setParticipants(participants);
    return this.rotate('leave');
  }

  close(): void {
    this.closed = true;
    this.participants.clear();
    this.early.length = 0;
  }

  /**
   * A key message from the server. Installed only if it is addressed to this
   * participant and device, comes from a current participant's device as the
   * directory names it, is newer than the last one from that sender, and
   * names a key id no other key used.
   */
  async receive(envelope: SignedVoiceKeyEnvelope, signature: string): Promise<boolean> {
    if (this.closed) return false;
    if (
      envelope.type !== 'voice-key'
      || envelope.channelId !== this.self.channelId
      || envelope.targetParticipantId !== this.self.participantId
      || envelope.targetDeviceId !== this.self.deviceId
      || !Number.isSafeInteger(envelope.sequence) || envelope.sequence < 1
      || !Number.isInteger(envelope.keyId) || envelope.keyId < 0 || envelope.keyId > MAX_KEY_ID
      || typeof envelope.wrappedKey !== 'string' || !WRAPPED_KEY.test(envelope.wrappedKey)
    ) return false;
    if (envelope.senderParticipantId === this.self.participantId) return false;
    const sender = this.participants.get(envelope.senderParticipantId);
    if (!sender) {
      // The message may have overtaken the news that its sender joined; it is
      // checked in full once the sender is in the call.
      this.early.push({ envelope, signature });
      if (this.early.length > MAX_EARLY_MESSAGES) this.early.shift();
      return false;
    }
    if (sender.deviceId !== envelope.senderDeviceId) return false;
    const identity = (await this.deps.identities([sender.deviceId]).catch(() => null))?.get(sender.deviceId);
    if (!identity || identity.userId !== sender.userId) return false;
    if (!await this.deps.verify(envelope, signature, identity.identityKey).catch(() => false)) return false;
    // The sender may have left, or been replaced, while this was checked.
    if (this.closed || this.participants.get(sender.participantId) !== sender) return false;
    const state = this.inbound.get(sender.participantId) ?? { deviceId: sender.deviceId, lastSequence: 0, keyIds: [] };
    if (state.deviceId !== sender.deviceId || envelope.sequence <= state.lastSequence) return false;
    const owner = this.keyOwners.get(envelope.keyId);
    if (owner !== undefined && (owner !== sender.participantId || state.keyIds.includes(envelope.keyId))) return false;
    state.lastSequence = envelope.sequence;
    this.inbound.set(sender.participantId, state);
    let key: Uint8Array;
    try {
      key = await this.deps.unwrapKey(envelope.wrappedKey);
    } catch {
      return false;
    }
    if (key.length !== KEY_BYTES || this.closed || this.participants.get(sender.participantId) !== sender) return false;
    if (this.keyOwners.has(envelope.keyId) && this.keyOwners.get(envelope.keyId) !== sender.participantId) return false;
    this.keyOwners.set(envelope.keyId, sender.participantId);
    state.keyIds.push(envelope.keyId);
    await this.deps.addReceiveKey(sender.participantId, envelope.keyId, key);
    key.fill(0);
    while (state.keyIds.length > RECEIVE_KEYS_PER_SENDER) {
      this.deps.removeReceiveKey(state.keyIds.shift()!);
    }
    return true;
  }

  private setParticipants(participants: VoiceKeyPeer[]): void {
    const next = new Map<string, VoiceKeyPeer>();
    for (const participant of participants) {
      if (participant.participantId === this.self.participantId) continue;
      const known = this.participants.get(participant.participantId);
      // A participant id names one device for the whole call.
      if (known && known.deviceId !== participant.deviceId) {
        this.forget(participant.participantId);
        continue;
      }
      next.set(participant.participantId, known ?? { ...participant });
    }
    for (const participantId of this.participants.keys()) {
      if (!next.has(participantId)) this.forget(participantId);
    }
    this.participants = next;
    const ready = this.early.filter((message) => next.has(message.envelope.senderParticipantId));
    if (ready.length) {
      this.early.splice(0, this.early.length, ...this.early.filter((message) => !ready.includes(message)));
      for (const message of ready) void this.receive(message.envelope, message.signature);
    }
  }

  private forget(participantId: string): void {
    this.early.splice(0, this.early.length, ...this.early.filter((message) => message.envelope.senderParticipantId !== participantId));
    this.participants.delete(participantId);
    this.inbound.delete(participantId);
    this.outboundSequences.delete(participantId);
    this.deps.removeParticipant(participantId);
  }

  /** Rotations run one at a time; each sends to the participants of its own moment. */
  private rotate(reason: 'start' | 'join' | 'leave'): Promise<void> {
    const run = this.queue.catch(() => undefined).then(() => this.rotateNow(reason));
    this.queue = run;
    return run;
  }

  private async rotateNow(reason: 'start' | 'join' | 'leave'): Promise<void> {
    if (this.closed) return;
    let keyId = this.deps.randomKeyId();
    for (let attempt = 0; this.keyOwners.has(keyId) || this.ownKeyIds.has(keyId); attempt += 1) {
      if (attempt >= 16) throw new Error('VOICE_KEY_ID_EXHAUSTED');
      keyId = this.deps.randomKeyId();
    }
    if (!Number.isInteger(keyId) || keyId < 0 || keyId > MAX_KEY_ID) throw new Error('VOICE_KEY_ID_INVALID');
    const key = this.deps.randomKey();
    if (key.length !== KEY_BYTES) throw new Error('VOICE_KEY_INVALID');
    this.ownKeyIds.add(keyId);
    this.keyOwners.set(keyId, this.self.participantId);
    const recipients = [...this.participants.values()];
    const identities = recipients.length
      ? await this.deps.identities(recipients.map((peer) => peer.deviceId)).catch(() => new Map<string, VoiceKeyIdentity>())
      : new Map<string, VoiceKeyIdentity>();
    await Promise.allSettled(recipients.map(async (peer) => {
      const identity = identities.get(peer.deviceId);
      if (!identity || identity.userId !== peer.userId) return false;
      const sequence = (this.outboundSequences.get(peer.participantId) ?? 0) + 1;
      this.outboundSequences.set(peer.participantId, sequence);
      const envelope: SignedVoiceKeyEnvelope = {
        type: 'voice-key',
        sequence,
        channelId: this.self.channelId,
        senderParticipantId: this.self.participantId,
        senderDeviceId: this.self.deviceId,
        targetParticipantId: peer.participantId,
        targetDeviceId: peer.deviceId,
        keyId,
        wrappedKey: await this.deps.wrapKey(key, identity.identityKey),
      };
      const signature = await this.deps.sign(envelope);
      // Checked again right before sending: no await between here and the send.
      if (this.closed || !this.participants.has(peer.participantId)) return false;
      return this.deps.send(envelope, signature);
    }));
    const recipientLeft = () => recipients.some((peer) => !this.participants.has(peer.participantId));
    if (this.closed || recipientLeft()) {
      key.fill(0);
      return;
    }
    if (reason === 'join' && this.currentKeyId !== null) await this.deps.delay(SWITCH_DELAY_MS);
    if (this.closed || recipientLeft()) {
      key.fill(0);
      return;
    }
    await this.deps.useSendKey(keyId, key);
    key.fill(0);
    this.currentKeyId = keyId;
  }
}
