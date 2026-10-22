import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { pendingDevicesToRetire } from './device-limit.js';

const approved = (id: string) => ({ id, approvedAt: new Date('2026-10-01T00:00:00Z') });
const pending = (id: string) => ({ id, approvedAt: null });

describe('making room under the device limit', () => {
  it('retires nothing while there is room', () => {
    assert.deepEqual(pendingDevicesToRetire([], 8), []);
    assert.deepEqual(pendingDevicesToRetire([approved('a'), pending('b')], 8), []);
    assert.deepEqual(pendingDevicesToRetire(Array.from({ length: 7 }, (_, i) => pending(`p${i}`)), 8), []);
  });

  it('retires the oldest pending device at the limit, so pending devices cannot fill an account', () => {
    // The audit's scenario: the owner's device plus seven registered by someone with the password.
    const active = [approved('phone'), ...Array.from({ length: 7 }, (_, i) => pending(`p${i}`))];
    assert.deepEqual(pendingDevicesToRetire(active, 8), ['p0']);
    // Oldest first, in the order given, not by id.
    const unordered = [pending('z'), approved('phone'), pending('a'), ...Array.from({ length: 5 }, (_, i) => approved(`d${i}`))];
    assert.deepEqual(pendingDevicesToRetire(unordered, 8), ['z']);
  });

  it('never retires an approved device, however old', () => {
    const active = [approved('oldest'), pending('p1'), ...Array.from({ length: 5 }, (_, i) => approved(`a${i}`)), pending('p7')];
    assert.deepEqual(pendingDevicesToRetire(active, 8), ['p1']);
    const onlyApproved = Array.from({ length: 8 }, (_, i) => approved(`a${i}`));
    assert.equal(pendingDevicesToRetire(onlyApproved, 8), null, 'the limit holds when every device is approved');
  });

  it('retires as many as needed if the account is over the limit, or none if they cannot make room', () => {
    const over = [approved('a'), pending('p1'), pending('p2'), pending('p3'), ...Array.from({ length: 5 }, (_, i) => approved(`b${i}`))];
    assert.deepEqual(pendingDevicesToRetire(over, 8), ['p1', 'p2']);
    const tooFew = [...Array.from({ length: 9 }, (_, i) => approved(`a${i}`)), pending('p')];
    assert.equal(pendingDevicesToRetire(tooFew, 8), null);
  });
});
