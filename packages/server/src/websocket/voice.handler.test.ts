import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

const { VoiceParticipantRegistry, parseVoiceSignal } = await import('./voice.handler.js');

const channelA = '00000000-0000-4000-8000-000000000001';
const channelB = '00000000-0000-4000-8000-000000000002';
const deviceA = '00000000-0000-4000-8000-000000000011';
const deviceB = '00000000-0000-4000-8000-000000000012';

describe('bounded voice participant registry', () => {
  it('bounds a channel, routes only current peers, and removes moved sockets', () => {
    const registry = new VoiceParticipantRegistry(2);
    const first = registry.join(
      'socket_a', 'user-a', deviceA, channelA,
      new Date('2026-08-27T00:00:00Z'), 'participant_a',
    );
    assert.equal(first.joined, true);
    assert.deepEqual(first.existing, []);
    const second = registry.join(
      'socket_b', 'user-b', deviceB, channelA,
      new Date('2026-08-27T00:00:01Z'), 'participant_b',
    );
    assert.deepEqual(second.existing.map((entry) => entry.participantId), ['participant_a']);
    assert.equal(registry.canRoute('socket_a', 'participant_b', channelA), true);
    assert.equal(registry.canRoute('socket_a', 'participant_a', channelA), false);
    const duplicate = registry.join('socket_a', 'user-a', deviceA, channelA);
    assert.equal(duplicate.joined, false);
    assert.equal(duplicate.participant.participantId, 'participant_a');
    assert.deepEqual(duplicate.existing.map((entry) => entry.participantId), ['participant_b']);
    assert.throws(
      () => registry.join('socket_c', 'user-c', '00000000-0000-4000-8000-000000000013', channelA),
      /VOICE_CHANNEL_FULL/,
    );

    const moved = registry.join('socket_a', 'user-a', deviceA, channelB, new Date(), 'participant_a_moved');
    assert.equal(moved.previous?.channelId, channelA);
    assert.equal(registry.canRoute('socket_a', 'participant_b', channelA), false);
    assert.deepEqual(registry.list(channelA).map((entry) => entry.participantId), ['participant_b']);
    assert.deepEqual(registry.list(channelB).map((entry) => entry.participantId), ['participant_a_moved']);

    registry.rollbackJoin('socket_a', moved.previous);
    assert.deepEqual(registry.list(channelA).map((entry) => entry.participantId), ['participant_a', 'participant_b']);
    assert.deepEqual(registry.list(channelB), []);
  });

  it('never reports a muted participant as speaking', () => {
    const registry = new VoiceParticipantRegistry();
    registry.join('socket_a', 'user-a', deviceA, channelA, new Date(), 'participant_a');
    assert.deepEqual(registry.update('socket_a', channelA, { muted: true, speaking: true }), {
      participantId: 'participant_a',
      userId: 'user-a',
      deviceId: deviceA,
      muted: true,
      speaking: false,
      joinedAt: registry.get('socket_a')!.joinedAt,
    });
    assert.equal(registry.update('socket_a', channelB, { muted: false, speaking: true }), null);
  });
});

describe('voice signaling admission', () => {
  it('accepts exact signed SDP shapes and rejects field confusion', () => {
    const valid = {
      type: 'voice-signal',
      signalId: '00000000-0000-4000-8000-000000000020',
      sequence: 1,
      channelId: channelA,
      senderParticipantId: 'socket_a',
      senderDeviceId: deviceA,
      targetParticipantId: 'socket_b',
      kind: 'offer',
      descriptionType: 'offer',
      sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB\r\n',
      candidate: null,
      sdpMid: null,
      sdpMLineIndex: null,
      usernameFragment: null,
      signature: `${'A'.repeat(86)}==`,
    };
    assert.equal(parseVoiceSignal(valid)?.envelope.kind, 'offer');
    assert.equal(parseVoiceSignal({ ...valid, targetParticipantId: '../room' }), null);
    assert.equal(parseVoiceSignal({ ...valid, kind: 'ice' }), null);
    assert.equal(parseVoiceSignal({ ...valid, sequence: 0 }), null);
    assert.equal(parseVoiceSignal({ ...valid, extra: true }), null);
    assert.equal(parseVoiceSignal({ ...valid, sdp: 'x'.repeat(32 * 1024 + 1) }), null);
  });
});
