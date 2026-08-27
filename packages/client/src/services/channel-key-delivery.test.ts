import { describe, expect, it } from 'vitest';
import { serializeChannelKeyAcknowledgement } from '@alparts/shared';
import type { ChannelKeyDelivery } from './api';
import {
  isDecryptableChannelKeyEpoch,
  orderChannelKeyDeliveries,
  tryChannelKeyDeliveries,
} from './crypto.service';

function delivery(deliveryId: string, epochStatus: ChannelKeyDelivery['epochStatus'] = 'pending'): ChannelKeyDelivery {
  return {
    deliveryId,
    version: 2,
    encryptedKey: 'wrapped',
    keyCommitment: 'commitment',
    distributorDeviceId: '11111111-1111-4111-8111-111111111111',
    distributorIdentityKey: '{}',
    signature: 'signature',
    epochStatus,
    confirmedAt: null,
    createdAt: '2026-08-27T00:00:00.000Z',
  };
}

describe('two-phase channel-key delivery selection', () => {
  it('tries immutable candidates in delivery-id order and skips invalid candidates', async () => {
    const attempted: string[] = [];
    const result = await tryChannelKeyDeliveries([
      delivery('cccccccc-cccc-4ccc-8ccc-cccccccccccc'),
      delivery('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
      delivery('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
    ], async (candidate) => {
      attempted.push(candidate.deliveryId);
      return candidate.deliveryId.startsWith('bbbb') ? 'valid key' : null;
    });

    expect(attempted).toEqual([
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    ]);
    expect(result).toMatchObject({
      delivery: { deliveryId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
      value: 'valid key',
    });
    expect(orderChannelKeyDeliveries([
      delivery('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
      delivery('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    ]).map((candidate) => candidate.deliveryId)).toEqual([
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    ]);
  });

  it('never classifies pending or aborted epochs as decryptable', () => {
    expect(isDecryptableChannelKeyEpoch('pending')).toBe(false);
    expect(isDecryptableChannelKeyEpoch('aborted')).toBe(false);
    expect(isDecryptableChannelKeyEpoch('active')).toBe(true);
    expect(isDecryptableChannelKeyEpoch('retired')).toBe(true);
  });

  it('binds an acknowledgement to the exact delivery and distributor', () => {
    const envelope = {
      deliveryId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      channelId: '22222222-2222-4222-8222-222222222222',
      keyVersion: 2,
      keyCommitment: 'commitment',
      recipientDeviceId: '33333333-3333-4333-8333-333333333333',
      distributorDeviceId: '44444444-4444-4444-8444-444444444444',
      encryptedKey: 'wrapped',
    };
    const serialized = serializeChannelKeyAcknowledgement(envelope);

    expect(serializeChannelKeyAcknowledgement({
      ...envelope,
      deliveryId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })).not.toBe(serialized);
    expect(serializeChannelKeyAcknowledgement({
      ...envelope,
      distributorDeviceId: '55555555-5555-4555-8555-555555555555',
    })).not.toBe(serialized);
  });
});
