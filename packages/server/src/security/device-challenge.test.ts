import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DeviceChallengeStore } from './device-challenge.js';

describe('device proof challenges', () => {
  it('binds a challenge to one user/session and consumes it exactly once', () => {
    const store = new DeviceChallengeStore();
    const challenge = store.issue('user-a', 'session-a', 100);
    assert.equal(store.consume('user-b', 'session-a', challenge, 101), false);
    assert.equal(store.consume('user-a', 'session-a', challenge, 102), false, 'a failed claim consumes the challenge');

    const replacement = store.issue('user-a', 'session-a', 200);
    assert.equal(store.consume('user-a', 'session-a', replacement, 201), true);
    assert.equal(store.consume('user-a', 'session-a', replacement, 202), false);
  });

  it('rejects expired or cross-session challenges', () => {
    const store = new DeviceChallengeStore();
    const challenge = store.issue('user-a', 'session-a', 0);
    assert.equal(store.consume('user-a', 'session-b', challenge, 1), false);
    assert.equal(store.consume('user-a', 'session-a', challenge, 5 * 60 * 1000), false);
  });
});
