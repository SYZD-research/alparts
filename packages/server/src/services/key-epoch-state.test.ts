import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  abortPendingChannelKeyEpochs,
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

  it('cleans a maximum workspace epoch batch with three ordered set operations', async () => {
    const aborted = Array.from({ length: 300 }, (_, index) => ({
      channelId: `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`,
      version: index + 1,
    }));
    const executed: unknown[] = [];
    const store = {
      update: () => ({
        set: () => ({
          where: () => ({ returning: async () => aborted }),
        }),
      }),
      execute: async (query: unknown) => {
        executed.push(query);
        return { rows: [] };
      },
    };

    const result = await abortPendingChannelKeyEpochs(store, aborted.map((epoch) => epoch.channelId));
    assert.equal(result.length, aborted.length);
    assert.equal(executed.length, 3, 'cleanup round trips must not grow with epoch count');
  });

  it('rejects an internal abort set above the bounded workspace channel maximum', async () => {
    const channelIds = Array.from({ length: 301 }, (_, index) => `channel-${index}`);
    await assert.rejects(abortPendingChannelKeyEpochs({}, channelIds), /KEY_EPOCH_ABORT_LIMIT/);
  });
});
