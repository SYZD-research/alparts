import { VoiceFrameCrypto, frameTransform, type VoiceFrameMessage } from './voice-frame-transform';

/**
 * Encrypts every audio frame this device sends to the media server and
 * decrypts every frame it receives (RTCRtpScriptTransform). The main thread
 * posts the keys; frames never reach the main thread.
 */
type TransformOptions = { direction: 'send' } | { direction: 'recv'; participantId: string };

interface RtcTransformEvent extends Event {
  transformer: {
    readable: ReadableStream<{ data: ArrayBuffer }>;
    writable: WritableStream<{ data: ArrayBuffer }>;
    options: TransformOptions;
  };
}

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<VoiceFrameMessage>) => void) | null;
  addEventListener(type: 'rtctransform', listener: (event: Event) => void): void;
};
const state = new VoiceFrameCrypto();

scope.onmessage = (event: MessageEvent<VoiceFrameMessage>) => {
  state.handle(event.data);
};

scope.addEventListener('rtctransform', (event) => {
  const { transformer } = event as RtcTransformEvent;
  const options = transformer.options;
  const transform = options?.direction === 'send'
    ? frameTransform((data) => state.encrypt(data))
    : options?.direction === 'recv' && typeof options.participantId === 'string'
      ? frameTransform((data) => state.decrypt(options.participantId, data))
      // Unknown streams pass nothing.
      : frameTransform(async () => null);
  void transformer.readable.pipeThrough(transform).pipeTo(transformer.writable).catch(() => undefined);
});
