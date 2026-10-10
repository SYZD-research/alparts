import { api } from '../services/api';
import { ensureDeviceSession } from '../services/crypto.service';
import { getRemoteVoiceStream, useVoiceStore } from '../stores/voice.store';

/**
 * Drives a real client for the SFU call check
 * (formal-model/conformance/voice-sfu-e2e.mts): the device is enrolled and
 * the call joined through the same code the app uses. Remote audio is played
 * by muted audio elements and measured with an analyser.
 */
interface Meter {
  stream: MediaStream;
  analyser: AnalyserNode;
  audio: HTMLAudioElement;
}

const meters = new Map<string, Meter>();
let audioContext: AudioContext | null = null;

// Control run: the frame worker is replaced by one that encrypts nothing, so
// the check can show that it notices plaintext frames.
if (new URLSearchParams(location.search).get('control') === 'plaintext-frames') {
  const RealWorker = window.Worker;
  window.Worker = class extends RealWorker {
    constructor(url: string | URL, options?: WorkerOptions) {
      super(String(url).includes('voice-frame') ? '/e2e/plaintext-frames.worker.js' : url, options);
    }
  };
}

function meter(participantId: string): Meter | null {
  const stream = getRemoteVoiceStream(participantId);
  if (!stream) return null;
  const existing = meters.get(participantId);
  if (existing?.stream === stream) return existing;
  existing?.audio.remove();
  audioContext ??= new AudioContext();
  void audioContext.resume();
  // Chromium feeds a remote stream to Web Audio only while a media element plays it.
  const audio = document.createElement('audio');
  audio.muted = true;
  audio.autoplay = true;
  audio.srcObject = stream;
  document.body.append(audio);
  void audio.play().catch(() => undefined);
  const analyser = audioContext.createAnalyser();
  analyser.fftSize = 2048;
  audioContext.createMediaStreamSource(stream).connect(analyser);
  const created = { stream, analyser, audio };
  meters.set(participantId, created);
  return created;
}

const harness = {
  async start(channelId: string) {
    const user = await api.getMe();
    await ensureDeviceSession(user);
    await useVoiceStore.getState().join(channelId);
    return harness.state();
  },
  state() {
    const state = useVoiceStore.getState();
    return {
      status: state.status,
      error: state.error,
      self: state.self?.participantId ?? null,
      participants: state.participants.map((participant) => participant.participantId),
      quality: state.quality,
    };
  },
  /** Peak level of a participant's audio over `ms` milliseconds (-1 without a stream). */
  async level(participantId: string, ms = 1500): Promise<number> {
    const deadline = performance.now() + ms;
    let peak = -1;
    const samples = new Float32Array(2048);
    while (performance.now() < deadline) {
      const entry = meter(participantId);
      if (entry) {
        entry.analyser.getFloatTimeDomainData(samples);
        let sum = 0;
        for (const sample of samples) sum += sample * sample;
        peak = Math.max(peak, Math.sqrt(sum / samples.length));
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return peak;
  },
  leave() {
    useVoiceStore.getState().leave();
    for (const entry of meters.values()) entry.audio.remove();
    meters.clear();
  },
};

(window as unknown as { voiceCall: typeof harness }).voiceCall = harness;
document.title = 'voice call test page ready';
