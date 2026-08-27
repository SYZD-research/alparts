import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  areRequiredRecipientsAcknowledged,
  nextChannelKeyVersion,
} from './key-epoch-state.js';

describe('channel key epoch state', () => {
  it('requires every frozen activation recipient to accept an exact delivery', () => {
    assert.equal(areRequiredRecipientsAcknowledged([]), false);
    assert.equal(areRequiredRecipientsAcknowledged([
      { requiredForActivation: true, acceptedDeliveryId: 'delivery-a' },
      { requiredForActivation: true, acceptedDeliveryId: null },
    ]), false);
    assert.equal(areRequiredRecipientsAcknowledged([
      { requiredForActivation: true, acceptedDeliveryId: 'delivery-a' },
      { requiredForActivation: true, acceptedDeliveryId: 'delivery-b' },
      { requiredForActivation: false, acceptedDeliveryId: null },
    ]), true);
  });

  it('never reuses an aborted or retired epoch version', () => {
    assert.equal(nextChannelKeyVersion(undefined), 1);
    assert.equal(nextChannelKeyVersion(null), 1);
    assert.equal(nextChannelKeyVersion(7), 8);
  });
});
