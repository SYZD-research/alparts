import { afterEach, describe, expect, it, vi } from 'vitest';

const played: number[][] = [];
let current: number[] = [];
const sinks: string[] = [];

class FakeAudioContext {
  state = 'running';
  currentTime = 0;
  destination = {};
  async resume() {}
  async setSinkId(id: string) { sinks.push(id); }
  createOscillator() {
    return {
      type: '',
      frequency: { value: 0 },
      connect: (node: unknown) => node,
      start() {},
      stop() {},
    };
  }
  createGain() {
    return { gain: { setValueAtTime() {}, exponentialRampToValueAtTime() {} }, connect: (node: unknown) => node };
  }
}

describe('call sounds', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
    played.length = 0;
    sinks.length = 0;
  });

  async function load() {
    vi.stubGlobal('AudioContext', class extends FakeAudioContext {
      createOscillator() {
        const oscillator = super.createOscillator();
        const frequency = { set value(hz: number) { current.push(hz); }, get value() { return 0; } };
        return { ...oscillator, frequency };
      }
    });
    return import('./voice-sounds');
  }

  function record(play: () => void): number[] {
    current = [];
    play();
    played.push(current);
    return current;
  }

  it('sounds different for our own join than for someone else joining, and rises for joining but falls for leaving', async () => {
    const { playVoiceCue } = await load();
    const selfJoin = record(() => playVoiceCue('self-join'));
    const peerJoin = record(() => playVoiceCue('peer-join'));
    const peerLeave = record(() => playVoiceCue('peer-leave'));
    expect(selfJoin).not.toEqual(peerJoin);
    expect(selfJoin).toEqual([...selfJoin].sort((a, b) => a - b));
    expect(peerLeave).toEqual([...peerJoin].reverse());
  });

  it('plays a lower note for muting than for unmuting, on the chosen speaker', async () => {
    const { playVoiceCue } = await load();
    const [mute] = record(() => playVoiceCue('mute', 'speaker-2'));
    const [unmute] = record(() => playVoiceCue('unmute', 'speaker-2'));
    expect(mute!).toBeLessThan(unmute!);
    expect(sinks).toEqual(['speaker-2']);
  });

  it('stays silent without audio output', async () => {
    vi.stubGlobal('AudioContext', undefined);
    const { playVoiceCue } = await import('./voice-sounds');
    expect(() => playVoiceCue('self-join')).not.toThrow();
  });
});
