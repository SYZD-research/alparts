import { describe, expect, it } from 'vitest';
import { mlsGroupId, serializeChannelKeyAcknowledgement } from '@alparts/shared';
import type { ChannelKeyDelivery, ChannelKeyRecipientState } from './api';
import {
  assertKeyRecipientState,
  channelKeyWait,
  ChannelKeyDeliveryPendingError,
  isDecryptableChannelKeyEpoch,
  isChannelKeyDeliveryPendingError,
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

describe('history key deliveries from before continuous groups', () => {
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

describe('waiting for a channel group', () => {
  it('classifies waiting to be added as recoverable availability, with its reason', () => {
    const waiting = new ChannelKeyDeliveryPendingError();
    expect(isChannelKeyDeliveryPendingError(waiting)).toBe(true);
    expect(isChannelKeyDeliveryPendingError({ code: waiting.code })).toBe(true);
    expect(isChannelKeyDeliveryPendingError(new Error('invalid signature'))).toBe(false);
    expect(channelKeyWait(waiting)).toEqual({ reason: 'waiting', freshStartAvailable: false });
    expect(channelKeyWait(new ChannelKeyDeliveryPendingError('rejoining', true)))
      .toEqual({ reason: 'rejoining', freshStartAvailable: true });
    expect(channelKeyWait(new ChannelKeyDeliveryPendingError('genesis-waiting')))
      .toEqual({ reason: 'genesis-waiting', freshStartAvailable: false });
    expect(channelKeyWait(new Error('INVALID_MLS_TRANSCRIPT'))).toBeNull();
  });

  it('never shows a device count or a technical term in the waiting state', () => {
    // The UI picks its own plain text from the reason; the error carries no text.
    expect(new ChannelKeyDeliveryPendingError('waiting').message).toBe('CHANNEL_KEY_DELIVERY_PENDING');
  });
});

describe('server key state of continuous groups', () => {
  const channelId = '22222222-2222-4222-8222-222222222222';
  const device = '33333333-3333-4333-8333-333333333333';
  const user = '44444444-4444-4444-8444-444444444444';
  const base = (): ChannelKeyRecipientState => ({
    protocolVersion: 4,
    pendingProtocolVersion: null,
    currentVersion: 7,
    keyCommitment: 'c'.repeat(43),
    pendingVersion: null,
    pendingKeyCommitment: null,
    pendingInvalid: false,
    nextVersion: 8,
    rotationRequired: false,
    historyRecoveryRequired: false,
    canRotate: true,
    canAbortPending: false,
    distributedDeviceIds: [device],
    pendingAcknowledgedDeviceIds: [],
    pendingRequiredDeviceIds: [],
    recipients: [{ deviceId: device, userId: user, identityKey: '{}' }],
    group: {
      genesisVersion: 5,
      groupId: mlsGroupId(channelId, 5),
      epoch: 3,
      transcript: 'a'.repeat(64),
      members: [{ deviceId: device, userId: user, leafIndex: 0 }],
    },
    ownMembership: { joinedVersion: 5, leafIndex: 0, rejoinRequested: false },
    pendingAddDeviceIds: [],
    requiredRemoveDeviceIds: [],
    updateRequired: false,
    ownLeafRefreshDue: false,
    canCommit: true,
    canCreate: false,
    genesisWaiting: [],
  });

  it('accepts a consistent group state', () => {
    expect(() => assertKeyRecipientState(channelId, base())).not.toThrow();
    expect(() => assertKeyRecipientState(channelId, {
      ...base(),
      group: null,
      ownMembership: null,
      canCommit: false,
      canCreate: true,
      currentVersion: 0,
      keyCommitment: null,
      nextVersion: 1,
    })).not.toThrow();
  });

  it('refuses a group named for another channel, a wrong epoch, pending versions and impossible memberships', () => {
    const state = base();
    expect(() => assertKeyRecipientState(channelId, { ...state, group: { ...state.group!, groupId: mlsGroupId(device, 5) } })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, group: { ...state.group!, epoch: 2 } })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, pendingVersion: 8, pendingKeyCommitment: 'x' })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, ownMembership: { joinedVersion: 9, leafIndex: 0, rejoinRequested: false } })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, ownMembership: { joinedVersion: 5, leafIndex: 0, rejoinRequested: true } })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, canCreate: true })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, group: null, ownMembership: null, canCommit: false, historyRecoveryRequired: true })).toThrow();
    expect(() => assertKeyRecipientState(channelId, { ...state, pendingAddDeviceIds: [device, device] })).toThrow();
  });
});
