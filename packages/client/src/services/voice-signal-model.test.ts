import { describe, expect, it } from 'vitest';
import { serializeVoiceSignalEnvelope } from '@alparts/shared';
import {
  VoiceSignalSequenceTracker,
  normalizeVoiceIceServers,
  parseIncomingVoiceSignal,
  parseVoiceJoinResult,
} from './voice-signal-model';

const envelope = {
  type: 'voice-signal' as const,
  signalId: '00000000-0000-4000-8000-000000000001',
  sequence: 1,
  channelId: '00000000-0000-4000-8000-000000000002',
  senderParticipantId: 'socket_a',
  senderDeviceId: '00000000-0000-4000-8000-000000000003',
  targetParticipantId: 'socket_b',
  kind: 'offer' as const,
  descriptionType: 'offer' as const,
  sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB\r\n',
  candidate: null,
  sdpMid: null,
  sdpMLineIndex: null,
  usernameFragment: null,
};

describe('voice signaling model', () => {
  it('keeps the signed representation stable and rejects confused shapes', () => {
    expect(serializeVoiceSignalEnvelope(envelope)).toBe(JSON.stringify([
      1, 'voice-signal', envelope.signalId, 1, envelope.channelId, 'socket_a',
      envelope.senderDeviceId, 'socket_b', 'offer', 'offer', envelope.sdp,
      null, null, null, null,
    ]));
    const wrapped = { envelope, signature: `${'A'.repeat(86)}==` };
    expect(parseIncomingVoiceSignal(wrapped)?.envelope).toEqual(envelope);
    expect(parseIncomingVoiceSignal({ ...wrapped, envelope: { ...envelope, targetParticipantId: '../room' } })).toBeNull();
    expect(parseIncomingVoiceSignal({ ...wrapped, envelope: { ...envelope, kind: 'ice' } })).toBeNull();
    expect(parseIncomingVoiceSignal({ ...wrapped, envelope: { ...envelope, sequence: 0 } })).toBeNull();
    expect(parseIncomingVoiceSignal({ ...wrapped, extra: true })).toBeNull();
  });

  it('bounds replay state and independently validates join/ICE configuration', () => {
    const tracker = new VoiceSignalSequenceTracker(2);
    expect(tracker.accept('socket_a', 1)).toBe(true);
    expect(tracker.accept('socket_a', 1)).toBe(false);
    expect(tracker.accept('socket_a', 2)).toBe(true);
    expect(tracker.accept('socket_b', 9)).toBe(true);
    expect(tracker.accept('socket_c', 1)).toBe(false);
    tracker.remove('socket_a');
    expect(tracker.accept('socket_c', 1)).toBe(true);

    const ice = [{ urls: ['turns:turn.example.test:5349?transport=tcp'], username: 'u', credential: 'c' }];
    expect(normalizeVoiceIceServers(ice)).toEqual(ice);
    expect(normalizeVoiceIceServers([{ urls: ['https://example.test'] }])).toBeNull();
    expect(parseVoiceJoinResult({
      ok: true,
      self: participant('socket_a'),
      participants: [participant('socket_b')],
      iceServers: ice,
    })?.participants?.length).toBe(1);
  });
});

function participant(participantId: string) {
  return {
    participantId,
    userId: '00000000-0000-4000-8000-000000000010',
    deviceId: '00000000-0000-4000-8000-000000000011',
    muted: false,
    speaking: false,
    joinedAt: '2026-08-27T00:00:00.000Z',
  };
}
