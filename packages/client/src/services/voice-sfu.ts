import { Device, type types as mediasoupTypes } from 'mediasoup-client';
import { MAX_VOICE_PARTICIPANTS } from '@alparts/shared';
import { deriveSFrameKey } from './sframe';
import type { VoiceFrameMessage } from './voice-frame-transform';
import {
  isSfuOk,
  parseSfuConsumer,
  parseSfuJoin,
  parseSfuProduced,
  parseSfuTransport,
  type SfuProducer,
} from './voice-sfu-model';

/** Asks the server (Socket.IO with acknowledgement); resolves to the raw answer. */
export type VoiceSfuRequest = (event: string, payload: unknown) => Promise<unknown>;

export interface VoiceSfuCallbacks {
  /** A participant's audio arrived (or ended, with null). */
  onRemoteStream(participantId: string, stream: MediaStream | null): void;
  /** Whether a participant is still in the call (streams of others are ignored). */
  isParticipant(participantId: string): boolean;
}

/** Whether this browser can encrypt and decrypt call audio frames. */
export function supportsFrameEncryption(): boolean {
  return typeof RTCRtpScriptTransform === 'function' && typeof Worker === 'function';
}

/**
 * Media of one call through the SFU. Audio is encrypted per frame in a
 * worker before it leaves this device, and decrypted there after it
 * arrives; a frame without a usable key is dropped, never passed on.
 */
export class VoiceSfuSession {
  private readonly worker: Worker;
  private device: Device | null = null;
  private sendTransport: mediasoupTypes.Transport | null = null;
  private recvTransport: mediasoupTypes.Transport | null = null;
  private producer: mediasoupTypes.Producer | null = null;
  private readonly consumers = new Map<string, mediasoupTypes.Consumer>();
  /** Streams announced before the session could consume them, or while it was consuming another. */
  private readonly announced = new Map<string, string>();
  private readonly consuming = new Set<string>();
  private ready = false;
  private closed = false;

  constructor(
    private readonly channelId: string,
    private readonly participantId: string,
    private readonly request: VoiceSfuRequest,
    private readonly callbacks: VoiceSfuCallbacks,
    private readonly iceServers: RTCIceServer[],
  ) {
    if (!supportsFrameEncryption()) throw new Error('FRAME_ENCRYPTION_UNSUPPORTED');
    this.worker = new Worker(new URL('./voice-frame.worker.ts', import.meta.url), { type: 'module' });
  }

  /** Install a key in the frame worker. */
  async installKey(kind: 'send', keyId: number, key: Uint8Array): Promise<void>;
  async installKey(kind: 'receive', keyId: number, key: Uint8Array, participantId: string): Promise<void>;
  async installKey(kind: 'send' | 'receive', keyId: number, key: Uint8Array, participantId?: string): Promise<void> {
    const derived = await deriveSFrameKey(key, BigInt(keyId));
    if (this.closed) return;
    this.post(kind === 'send'
      ? { type: 'send-key', keyId, key: derived.key, salt: derived.salt }
      : { type: 'receive-key', participantId: participantId!, keyId, key: derived.key, salt: derived.salt });
  }

  removeKey(keyId: number): void {
    this.post({ type: 'remove-key', keyId });
  }

  removeParticipantKeys(participantId: string): void {
    this.post({ type: 'remove-participant', participantId });
  }

  /** Join the SFU, open both transports, send this track and receive everyone already sending. */
  async start(track: MediaStreamTrack): Promise<void> {
    const joined = parseSfuJoin(
      await this.request('voice:sfu:join', { channelId: this.channelId }),
      this.participantId,
      MAX_VOICE_PARTICIPANTS - 1,
    );
    if (!joined) throw new Error('SFU_JOIN_FAILED');
    this.assertOpen();
    const device = new Device();
    await device.load({ routerRtpCapabilities: joined.rtpCapabilities as unknown as mediasoupTypes.RtpCapabilities });
    if (!device.canProduce('audio')) throw new Error('SFU_AUDIO_UNSUPPORTED');
    this.assertOpen();
    this.device = device;
    this.sendTransport = await this.openTransport('send');
    this.recvTransport = await this.openTransport('recv');
    this.producer = await this.sendTransport.produce({
      track,
      stopTracks: false,
      codecOptions: { opusDtx: true, opusFec: true },
      // Set before the sender carries any media: nothing leaves unencrypted.
      onRtpSender: (sender) => this.encrypt(sender),
    });
    this.assertOpen();
    this.ready = true;
    for (const producer of joined.producers) this.announced.set(producer.participantId, producer.producerId);
    await this.consumeAnnounced();
  }

  /** Someone in the call started sending. */
  announce(producer: SfuProducer): Promise<void> {
    if (producer.participantId === this.participantId || this.closed) return Promise.resolve();
    this.announced.set(producer.participantId, producer.producerId);
    return this.ready ? this.consumeAnnounced() : Promise.resolve();
  }

  /** A participant left: stop receiving it and forget its keys. */
  removeParticipant(participantId: string): void {
    this.announced.delete(participantId);
    this.removeParticipantKeys(participantId);
    const consumer = this.consumers.get(participantId);
    if (!consumer) return;
    this.consumers.delete(participantId);
    consumer.close();
    this.callbacks.onRemoteStream(participantId, null);
  }

  async replaceTrack(track: MediaStreamTrack): Promise<void> {
    if (!this.producer) throw new Error('SFU_NOT_SENDING');
    await this.producer.replaceTrack({ track });
  }

  /** Transport statistics, for the connection quality shown in the call panel. */
  async stats(): Promise<RTCStatsReport[]> {
    const transports = [this.sendTransport, this.recvTransport].filter((entry): entry is mediasoupTypes.Transport => Boolean(entry));
    return Promise.all(transports.map((transport) => transport.getStats()));
  }

  connectionStates(): string[] {
    return [this.sendTransport, this.recvTransport].flatMap((transport) => (transport ? [transport.connectionState] : []));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.ready = false;
    for (const [participantId, consumer] of this.consumers) {
      consumer.close();
      this.callbacks.onRemoteStream(participantId, null);
    }
    this.consumers.clear();
    this.announced.clear();
    this.producer?.close();
    this.sendTransport?.close();
    this.recvTransport?.close();
    this.post({ type: 'clear' });
    this.worker.terminate();
  }

  private post(message: VoiceFrameMessage): void {
    if (!this.closed || message.type === 'clear') this.worker.postMessage(message);
  }

  private encrypt(sender: RTCRtpSender): void {
    (sender as RTCRtpSender & { transform: unknown }).transform = new RTCRtpScriptTransform(this.worker, { direction: 'send' });
  }

  private decrypt(receiver: RTCRtpReceiver, participantId: string): void {
    (receiver as RTCRtpReceiver & { transform: unknown }).transform = new RTCRtpScriptTransform(this.worker, { direction: 'recv', participantId });
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('SFU_SESSION_CLOSED');
  }

  private async openTransport(direction: 'send' | 'recv'): Promise<mediasoupTypes.Transport> {
    const parameters = parseSfuTransport(await this.request('voice:sfu:transport', { channelId: this.channelId, direction }));
    if (!parameters) throw new Error('SFU_TRANSPORT_FAILED');
    this.assertOpen();
    const options = {
      id: parameters.id,
      iceParameters: parameters.iceParameters as unknown as mediasoupTypes.IceParameters,
      iceCandidates: parameters.iceCandidates as unknown as mediasoupTypes.IceCandidate[],
      dtlsParameters: parameters.dtlsParameters as unknown as mediasoupTypes.DtlsParameters,
      iceServers: this.iceServers,
    };
    const transport = direction === 'send' ? this.device!.createSendTransport(options) : this.device!.createRecvTransport(options);
    transport.on('connect', ({ dtlsParameters }, callback, errback) => {
      void this.request('voice:sfu:connect', { channelId: this.channelId, direction, transportId: transport.id, dtlsParameters })
        .then((answer) => (isSfuOk(answer) ? callback() : errback(new Error('SFU_CONNECT_FAILED'))), errback);
    });
    if (direction === 'send') {
      transport.on('produce', ({ rtpParameters }, callback, errback) => {
        void this.request('voice:sfu:produce', { channelId: this.channelId, rtpParameters })
          .then((answer) => {
            const producerId = parseSfuProduced(answer);
            if (producerId) callback({ id: producerId });
            else errback(new Error('SFU_PRODUCE_FAILED'));
          }, errback);
      });
    }
    return transport;
  }

  /** Receive each announced stream once, one request at a time per participant. */
  private async consumeAnnounced(): Promise<void> {
    // A snapshot: entries change while a stream is being received.
    for (const [participantId, producerId] of Array.from(this.announced)) {
      if (this.consuming.has(participantId)) continue;
      if (this.consumers.get(participantId)?.producerId === producerId) {
        this.announced.delete(participantId);
        continue;
      }
      this.consuming.add(participantId);
      try {
        await this.consume(participantId, producerId);
      } catch {
        // The participant may have left meanwhile; its next stream is announced again.
      } finally {
        this.consuming.delete(participantId);
        if (this.announced.get(participantId) === producerId) this.announced.delete(participantId);
      }
    }
    // A stream announced while another was being received.
    if ([...this.announced.keys()].some((participantId) => !this.consuming.has(participantId)) && this.ready) {
      await this.consumeAnnounced();
    }
  }

  private async consume(participantId: string, producerId: string): Promise<void> {
    if (!this.callbacks.isParticipant(participantId) || !this.device || !this.recvTransport) return;
    const parameters = parseSfuConsumer(await this.request('voice:sfu:consume', {
      channelId: this.channelId,
      sourceParticipantId: participantId,
      rtpCapabilities: this.device.rtpCapabilities,
    }), producerId);
    if (!parameters) throw new Error('SFU_CONSUME_FAILED');
    this.assertOpen();
    const consumer = await this.recvTransport.consume({
      id: parameters.id,
      producerId: parameters.producerId,
      kind: 'audio',
      rtpParameters: parameters.rtpParameters as unknown as mediasoupTypes.RtpParameters,
      // Set before the receiver hands any frame to the decoder.
      onRtpReceiver: (receiver) => this.decrypt(receiver, participantId),
    });
    if (this.closed || !this.callbacks.isParticipant(participantId)) {
      consumer.close();
      return;
    }
    this.consumers.get(participantId)?.close();
    this.consumers.set(participantId, consumer);
    this.callbacks.onRemoteStream(participantId, new MediaStream([consumer.track]));
    // The server holds the stream paused until the decrypting transform is in place.
    if (!isSfuOk(await this.request('voice:sfu:resume', { channelId: this.channelId, consumerId: consumer.id }))) {
      throw new Error('SFU_RESUME_FAILED');
    }
  }
}
