import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { sql, type SQL } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';
import {
  abortPendingChannelKeyEpochs,
  areRequiredRecipientsAcknowledged,
  deleteEpochRecipients,
  nextChannelKeyVersion,
} from './key-epoch-state.js';

const dialect = new PgDialect();
const rendered = (query: SQL) => {
  const { sql: text, params } = dialect.sqlToQuery(query);
  return { text: text.replace(/\s+/g, ' ').trim(), params };
};

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
    assert.deepEqual(
      executed.map((query) => rendered(query as SQL).params.length),
      [600, 600, 600],
      'every statement covers every aborted epoch',
    );
  });

  it('clears acknowledgements before deleting deliveries, and deliveries before recipients', async () => {
    const executed: string[] = [];
    const store = {
      execute: async (query: SQL) => {
        executed.push(rendered(query).text);
        return { rows: [] };
      },
    };

    await deleteEpochRecipients(store, sql`channel_id = ${'00000000-0000-4000-8000-000000000001'}`);
    assert.deepEqual(executed, [
      'update "channel_key_epoch_recipients" set accepted_delivery_id = null, acknowledgement_signature = null, acknowledged_at = null where channel_id = $1',
      'delete from "channel_keys" where channel_id = $1',
      'delete from "channel_key_epoch_recipients" where channel_id = $1',
    ]);
  });

  it('rejects an internal abort set above the bounded workspace channel maximum', async () => {
    const channelIds = Array.from({ length: 301 }, (_, index) => `channel-${index}`);
    await assert.rejects(abortPendingChannelKeyEpochs({}, channelIds), /KEY_EPOCH_ABORT_LIMIT/);
  });
});
