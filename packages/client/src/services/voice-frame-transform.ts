import {
  SFrameReplayWindow,
  sframeDecrypt,
  sframeEncrypt,
  sframeHeader,
  type SFrameKey,
} from './sframe';

/**
 * Frame encryption state of one call, as kept by the transform worker
 * (voice-frame.worker.ts). Nothing leaves without the current send key, and
 * a received frame is passed on only when it decrypts under a key of the
 * participant whose stream it arrived on, with a counter not seen before.
 */
export type VoiceFrameMessage =
  | { type: 'send-key'; keyId: number; key: CryptoKey; salt: Uint8Array }
  | { type: 'receive-key'; participantId: string; keyId: number; key: CryptoKey; salt: Uint8Array }
  | { type: 'remove-key'; keyId: number }
  | { type: 'remove-participant'; participantId: string }
  | { type: 'clear' };

interface ReceiveKey {
  participantId: string;
  key: SFrameKey;
  replay: SFrameReplayWindow;
}

export class VoiceFrameCrypto {
  private send: { key: SFrameKey; counter: bigint } | null = null;
  private readonly receive = new Map<bigint, ReceiveKey>();

  handle(message: VoiceFrameMessage): void {
    switch (message.type) {
      case 'send-key':
        // A new key starts its own counter at zero.
        this.send = { key: { kid: BigInt(message.keyId), key: message.key, salt: message.salt }, counter: 0n };
        return;
      case 'receive-key': {
        const kid = BigInt(message.keyId);
        const existing = this.receive.get(kid);
        if (existing && existing.participantId !== message.participantId) return;
        this.receive.set(kid, {
          participantId: message.participantId,
          key: { kid, key: message.key, salt: message.salt },
          replay: existing?.replay ?? new SFrameReplayWindow(),
        });
        return;
      }
      case 'remove-key':
        this.receive.delete(BigInt(message.keyId));
        return;
      case 'remove-participant':
        for (const [kid, entry] of this.receive) {
          if (entry.participantId === message.participantId) this.receive.delete(kid);
        }
        return;
      case 'clear':
        this.send = null;
        this.receive.clear();
    }
  }

  /** The SFrame ciphertext of an outgoing frame, or null to drop it. */
  async encrypt(frame: ArrayBuffer): Promise<ArrayBuffer | null> {
    const state = this.send;
    if (!state) return null;
    const ctr = state.counter;
    state.counter += 1n;
    return (await sframeEncrypt(state.key, ctr, new Uint8Array(frame))).buffer;
  }

  /** The plaintext of a frame from `participantId`'s stream, or null to drop it. */
  async decrypt(participantId: string, frame: ArrayBuffer): Promise<ArrayBuffer | null> {
    const data = new Uint8Array(frame);
    const header = sframeHeader(data);
    if (!header) return null;
    const entry = this.receive.get(header.kid);
    if (!entry || entry.participantId !== participantId || !entry.replay.isFresh(header.ctr)) return null;
    const plaintext = await sframeDecrypt(entry.key, data);
    // The key may have been removed while decrypting.
    if (!plaintext || this.receive.get(header.kid) !== entry || !entry.replay.isFresh(header.ctr)) return null;
    entry.replay.accept(header.ctr);
    return plaintext.slice().buffer;
  }

  /** Whether a send key is installed (for tests and diagnostics). */
  hasSendKey(): boolean {
    return this.send !== null;
  }
}

/** A transform stream over encoded frames that drops what `process` refuses. */
export function frameTransform<T extends { data: ArrayBuffer }>(
  process: (data: ArrayBuffer) => Promise<ArrayBuffer | null>,
): TransformStream<T, T> {
  return new TransformStream<T, T>({
    async transform(frame, controller) {
      let data: ArrayBuffer | null = null;
      try {
        data = await process(frame.data);
      } catch {
        data = null;
      }
      if (!data) return;
      frame.data = data;
      controller.enqueue(frame);
    },
  });
}
