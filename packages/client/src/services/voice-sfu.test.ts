import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const devices: FakeDevice[] = [];

class FakeTransport {
  closed = false;
  connectionState = 'new';
  constructor(readonly id: string) {}
  on() {}
  close() { this.closed = true; }
  async produce() { return { id: '00000000-0000-4000-8000-0000000000f1', close: vi.fn() }; }
}

class FakeDevice {
  transports: FakeTransport[] = [];
  constructor() { devices.push(this); }
  async load() {}
  canProduce() { return true; }
  get rtpCapabilities() { return {}; }
  createSendTransport(options: { id: string }) { return this.add(options.id); }
  createRecvTransport(options: { id: string }) { return this.add(options.id); }
  private add(id: string) {
    const transport = new FakeTransport(id);
    this.transports.push(transport);
    return transport;
  }
}

vi.mock('mediasoup-client', () => ({ Device: FakeDevice }));

const { VoiceSfuSession } = await import('./voice-sfu');

const channelId = '00000000-0000-4000-8000-0000000000a1';
const participantId = 'participant_a';

function answers() {
  let transport = 0;
  return vi.fn(async (event: string, _payload?: unknown) => {
    if (event === 'voice:sfu:join') return { ok: true, participantId, rtpCapabilities: {}, producers: [] };
    if (event === 'voice:sfu:transport') {
      transport += 1;
      return { ok: true, transport: { id: `00000000-0000-4000-8000-00000000000${transport}`, iceParameters: {}, iceCandidates: [], dtlsParameters: {} } };
    }
    return { ok: true };
  });
}

describe('call media through the media server', () => {
  const terminate = vi.fn();

  beforeEach(() => {
    devices.length = 0;
    terminate.mockReset();
    vi.stubGlobal('RTCRtpScriptTransform', class {});
    vi.stubGlobal('Worker', class { postMessage() {} terminate() { terminate(); } });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('connects again from the start after the media server lost the call, keeping the frame keys', async () => {
    const request = answers();
    const session = new VoiceSfuSession(channelId, participantId, request, { onRemoteStream: vi.fn(), isParticipant: () => true }, []);
    const track = {} as MediaStreamTrack;
    await session.start(track);
    await session.restart(track);

    expect(request.mock.calls.map(([event]) => event).filter((event) => event === 'voice:sfu:join')).toHaveLength(2);
    expect(devices).toHaveLength(2);
    expect(devices[0]!.transports.every((transport) => transport.closed)).toBe(true);
    expect(devices[1]!.transports.map((transport) => transport.id)).toEqual(['00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004']);
    // The frame worker, which holds the keys, is the same one.
    expect(terminate).not.toHaveBeenCalled();
    session.close();
    expect(terminate).toHaveBeenCalledOnce();
  });

  it('stops a connection still being opened when a restart begins', async () => {
    let releaseJoin: () => void = () => undefined;
    const base = answers();
    let first = true;
    const request = vi.fn(async (event: string, payload: unknown) => {
      if (event === 'voice:sfu:join' && first) {
        first = false;
        await new Promise<void>((resolve) => { releaseJoin = resolve; });
      }
      return base(event, payload);
    });
    const session = new VoiceSfuSession(channelId, participantId, request, { onRemoteStream: vi.fn(), isParticipant: () => true }, []);
    const track = {} as MediaStreamTrack;
    const starting = session.start(track);
    const restarting = session.restart(track);
    releaseJoin();
    await expect(starting).rejects.toThrow('SFU_SESSION_RESTARTED');
    await restarting;
    expect(devices).toHaveLength(1);
    session.close();
  });
});
