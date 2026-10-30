/**
 * Short call cues, synthesized so that no audio files ship with the app.
 * Each cue is a few sine notes; rising for joining or unmuting, falling for
 * leaving or muting.
 */
export type VoiceCue = 'self-join' | 'self-leave' | 'peer-join' | 'peer-leave' | 'mute' | 'unmute';

interface Note {
  /** Frequency in Hz. */
  frequency: number;
  /** Start, from the beginning of the cue, in seconds. */
  at: number;
  duration: number;
}

const CUES: Record<VoiceCue, Note[]> = {
  // Three notes for our own join and leave, two for someone else's.
  'self-join': [
    { frequency: 523.25, at: 0, duration: 0.12 },
    { frequency: 659.25, at: 0.09, duration: 0.12 },
    { frequency: 783.99, at: 0.18, duration: 0.2 },
  ],
  'self-leave': [
    { frequency: 783.99, at: 0, duration: 0.12 },
    { frequency: 659.25, at: 0.09, duration: 0.12 },
    { frequency: 523.25, at: 0.18, duration: 0.2 },
  ],
  'peer-join': [
    { frequency: 587.33, at: 0, duration: 0.1 },
    { frequency: 880, at: 0.08, duration: 0.16 },
  ],
  'peer-leave': [
    { frequency: 880, at: 0, duration: 0.1 },
    { frequency: 587.33, at: 0.08, duration: 0.16 },
  ],
  mute: [{ frequency: 392, at: 0, duration: 0.09 }],
  unmute: [{ frequency: 659.25, at: 0, duration: 0.09 }],
};

const VOLUME = 0.12;

let context: AudioContext | null = null;
let contextSinkId = '';

/** Play a cue on the given output device ('' for the default). Never throws: a cue is not worth failing a call over. */
export function playVoiceCue(cue: VoiceCue, sinkId = ''): void {
  try {
    if (typeof AudioContext !== 'function') return;
    context ??= new AudioContext();
    const audio = context;
    if (audio.state === 'suspended') void audio.resume().catch(() => undefined);
    if (sinkId !== contextSinkId && 'setSinkId' in audio) {
      contextSinkId = sinkId;
      void (audio as AudioContext & { setSinkId(id: string): Promise<void> }).setSinkId(sinkId).catch(() => undefined);
    }
    const start = audio.currentTime + 0.01;
    for (const note of CUES[cue]) {
      const oscillator = audio.createOscillator();
      const gain = audio.createGain();
      oscillator.type = 'sine';
      oscillator.frequency.value = note.frequency;
      const begin = start + note.at;
      const end = begin + note.duration;
      // A short attack and an exponential release keep the notes free of clicks.
      gain.gain.setValueAtTime(0.0001, begin);
      gain.gain.exponentialRampToValueAtTime(VOLUME, begin + 0.012);
      gain.gain.exponentialRampToValueAtTime(0.0001, end);
      oscillator.connect(gain).connect(audio.destination);
      oscillator.start(begin);
      oscillator.stop(end + 0.02);
    }
  } catch {
    // No audio output available.
  }
}
