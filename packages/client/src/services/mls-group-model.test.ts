import { describe, expect, it } from 'vitest';
import { mlsGroupId, type MlsGroupCommit } from '@alparts/shared';
import {
  assertChainLink,
  assertEnvelopeStructure,
  assertGroupAfterChain,
  assertHeadsMonotonic,
  assertTreeMatchesRoster,
  CLIENT_REJOIN_LIMIT,
  genesisRoster,
  isGroupEquivocation,
  lowestFreeLeaves,
  nextRoster,
  recentRejoins,
  REJOIN_WINDOW_MS,
  requiresGroupKey,
  usersToVerify,
  type PreviousGroupView,
} from './mls-group-model';
import type { DecodedChannelCommit } from './mls-crypto';

const channelId = '11111111-1111-4111-8111-111111111111';
const users = { u1: 'aaaaaaaa-0000-4000-8000-000000000001', u2: 'aaaaaaaa-0000-4000-8000-000000000002' };
const head = (userId: string, sequence: number) => ({ userId, sequence, hash: String(sequence).padStart(64, '0') });

const previous: PreviousGroupView = {
  genesisVersion: 4,
  groupId: mlsGroupId(channelId, 4),
  version: 6,
  epoch: 3,
  transcript: 'a'.repeat(64),
  members: [
    { deviceId: 'd0', userId: users.u1, leafIndex: 0 },
    { deviceId: 'd1', userId: users.u2, leafIndex: 1 },
    { deviceId: 'd2', userId: users.u2, leafIndex: 2 },
  ],
  directoryHeads: [head(users.u1, 3), head(users.u2, 5)],
};

function commit(change: Partial<MlsGroupCommit> = {}): MlsGroupCommit {
  return {
    channelId,
    version: 7,
    previousVersion: 6,
    previousTranscript: 'a'.repeat(64),
    groupId: mlsGroupId(channelId, 4),
    epoch: 4,
    kind: 'commit',
    keyCommitment: 'k'.repeat(43),
    commit: '',
    welcome: 'W',
    added: [{ deviceId: 'd3', userId: users.u1, identityKey: '{}', packageId: 'p', keyPackage: 'KP3', signature: 's' }],
    removed: ['d1'],
    members: [
      { deviceId: 'd0', userId: users.u1, leafIndex: 0 },
      { deviceId: 'd3', userId: users.u1, leafIndex: 1 },
      { deviceId: 'd2', userId: users.u2, leafIndex: 2 },
    ],
    directoryHeads: [head(users.u1, 4), head(users.u2, 6)],
    committerDeviceId: 'd0',
    signature: 'x',
    ...change,
  };
}

function decoded(change: Partial<DecodedChannelCommit> = {}): DecodedChannelCommit {
  return {
    groupId: mlsGroupId(channelId, 4),
    epoch: 3,
    senderLeafIndex: 0,
    addPackages: ['KP3'],
    removedLeaves: [1],
    hasPath: true,
    ...change,
  };
}

const failure = (run: () => void) => {
  try {
    run();
  } catch (error) {
    return (error as Error).message;
  }
  return null;
};

describe('roster arithmetic', () => {
  it('fills the lowest free leaves in Add order, after Removes free theirs', () => {
    expect(lowestFreeLeaves([0, 2, 3], 3)).toEqual([1, 4, 5]);
    const roster = nextRoster(previous.members, ['d1', 'd0'], [
      { deviceId: 'g', userId: users.u1 },
      { deviceId: 'h', userId: users.u1 },
      { deviceId: 'i', userId: users.u2 },
    ]);
    expect(roster.map((member) => [member.deviceId, member.leafIndex])).toEqual([['g', 0], ['h', 1], ['d2', 2], ['i', 3]]);
    expect(genesisRoster([{ deviceId: 'c', userId: users.u1 }, { deviceId: 'b', userId: users.u2 }]))
      .toEqual([{ deviceId: 'c', userId: users.u1, leafIndex: 0 }, { deviceId: 'b', userId: users.u2, leafIndex: 1 }]);
  });

  it('accepts a removal whose leaf an addition reuses, and refuses any other roster', () => {
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded(), previous))).toBeNull();
    const swapped = commit({ members: commit().members.map((member) => ({ ...member, leafIndex: 2 - member.leafIndex })).reverse() });
    expect(failure(() => assertEnvelopeStructure(channelId, swapped, decoded(), previous))).toBe('INVALID_MLS_ROSTER');
    // A remove proposal for another leaf than the envelope names.
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded({ removedLeaves: [2] }), previous))).toBe('INVALID_MLS_ROSTER');
    // The sender must be the committer's leaf, and the committer cannot leave.
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded({ senderLeafIndex: 2 }), previous))).toBe('INVALID_MLS_ROSTER');
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ removed: ['d0', 'd1'] }), decoded(), previous))).toBe('INVALID_MLS_ROSTER');
    // Re-adding a member is a rejoin only when the same commit removes it.
    const readd = commit({
      added: [{ ...commit().added[0], deviceId: 'd2', userId: users.u2 }],
      removed: ['d1'],
    });
    expect(failure(() => assertEnvelopeStructure(channelId, readd, decoded(), previous))).toBe('INVALID_MLS_ROSTER');
  });

  it('refuses an added package other than the proposal carries and a group or epoch that does not continue', () => {
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded({ addPackages: ['other'] }), previous))).toBe('INVALID_MLS_ROSTER');
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ epoch: 5, version: 8 }), decoded({ epoch: 4 }), previous))).toBe('INVALID_MLS_GROUP');
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ groupId: mlsGroupId(channelId, 3) }), decoded(), previous))).toBe('INVALID_MLS_GROUP');
    expect(failure(() => assertEnvelopeStructure('22222222-2222-4222-8222-222222222222', commit(), decoded(), previous))).toBe('INVALID_MLS_GROUP');
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ previousTranscript: 'b'.repeat(64) }), decoded(), previous))).toBe('INVALID_MLS_TRANSCRIPT');
  });

  it('joins at a commit only when it follows the previous version and its sender is the committer', () => {
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded(), null))).toBeNull();
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ previousVersion: 5 }), decoded(), null))).toBe('INVALID_MLS_TRANSCRIPT');
    // d2 sits at leaf 2: a commit sent from it cannot name d0 as its committer.
    expect(failure(() => assertEnvelopeStructure(channelId, commit(), decoded({ senderLeafIndex: 2 }), null))).toBe('INVALID_MLS_ROSTER');
    expect(failure(() => assertEnvelopeStructure(channelId, commit({ committerDeviceId: 'd2' }), decoded({ senderLeafIndex: 2 }), null))).toBeNull();
  });

  it('checks a tree against the roster and the authenticated signature keys', () => {
    const auth = new Map([['d0', 'K0'], ['d3', 'K3'], ['d2', 'K2']]);
    const leaves = commit().members.map((member) => ({ ...member, signatureKey: auth.get(member.deviceId)! }));
    expect(failure(() => assertTreeMatchesRoster(leaves, commit().members, auth))).toBeNull();
    expect(failure(() => assertTreeMatchesRoster(leaves, commit().members, new Map([...auth, ['d3', 'other']])))).toBe('INVALID_MLS_ROSTER');
    expect(failure(() => assertTreeMatchesRoster(leaves.slice(1), commit().members, auth))).toBe('INVALID_MLS_ROSTER');
  });
});

describe('chain and directory heads', () => {
  const chain = { version: 6, transcript: 'a'.repeat(64) };

  it('moves only forward from the pin and links to its transcript', () => {
    expect(failure(() => assertChainLink(null, commit()))).toBeNull();
    expect(failure(() => assertChainLink(chain, commit()))).toBeNull();
    expect(failure(() => assertChainLink(chain, commit({ previousTranscript: 'b'.repeat(64) })))).toBe('INVALID_MLS_TRANSCRIPT');
    // A later join may skip versions this device could not read, never go back.
    expect(failure(() => assertChainLink(chain, commit({ version: 12, previousVersion: 11 })))).toBeNull();
    expect(failure(() => assertChainLink(chain, commit({ version: 6, previousVersion: 5 })))).toBe('INVALID_MLS_TRANSCRIPT');
    expect(failure(() => assertChainLink(chain, commit({ version: 9, previousVersion: 5 })))).toBe('INVALID_MLS_TRANSCRIPT');
    // The pinned envelope itself may be read again, with the same transcript only.
    expect(failure(() => assertChainLink(chain, commit({ version: 6, previousVersion: 5 }), 'a'.repeat(64)))).toBeNull();
    expect(failure(() => assertChainLink(chain, commit({ version: 6, previousVersion: 5 }), 'c'.repeat(64)))).toBe('INVALID_MLS_TRANSCRIPT');
    expect(isGroupEquivocation(new Error('INVALID_MLS_TRANSCRIPT'))).toBe(true);
    expect(isGroupEquivocation(new Error('CryptoVerificationError'))).toBe(false);
  });

  it('accepts a group at or below the pin only when it is the pinned group', () => {
    // Pinned at version 10 of the group that started at 4 (for example its removal of this device).
    const pinned = { version: 10, genesisVersion: 4 };
    expect(failure(() => assertGroupAfterChain(null, 1))).toBeNull();
    expect(failure(() => assertGroupAfterChain(pinned, 4))).toBeNull();
    expect(failure(() => assertGroupAfterChain(pinned, 11))).toBeNull();
    // A group that started before the pin and is not the pinned one branches off verified history.
    expect(failure(() => assertGroupAfterChain(pinned, 1))).toBe('INVALID_MLS_TRANSCRIPT');
    expect(failure(() => assertGroupAfterChain(pinned, 10))).toBe('INVALID_MLS_TRANSCRIPT');
    // A pin from before continuous groups: every group starts after it.
    expect(failure(() => assertGroupAfterChain({ version: 10, genesisVersion: null }, 10))).toBe('INVALID_MLS_TRANSCRIPT');
    expect(failure(() => assertGroupAfterChain({ version: 10, genesisVersion: null }, 11))).toBeNull();
  });

  it('never accepts an older directory head and re-verifies only changed users', () => {
    expect(failure(() => assertHeadsMonotonic(previous.directoryHeads, commit().directoryHeads))).toBeNull();
    expect(failure(() => assertHeadsMonotonic(previous.directoryHeads, [head(users.u1, 2)]))).toBe('DIRECTORY_INVALID');
    expect(failure(() => assertHeadsMonotonic(previous.directoryHeads, [{ ...head(users.u1, 3), hash: 'f'.repeat(64) }]))).toBe('DIRECTORY_INVALID');
    const unchanged = commit({ directoryHeads: previous.directoryHeads, added: [], removed: [], members: previous.members });
    expect(usersToVerify(previous.directoryHeads, unchanged)).toEqual([users.u1]);
    expect(usersToVerify(previous.directoryHeads, commit())).toEqual([users.u1, users.u2].sort());
    expect(usersToVerify(null, unchanged)).toEqual([users.u1, users.u2].sort());
  });
});

describe('client limits', () => {
  it('counts rejoins within one day, each accepted package once', () => {
    const now = 10 * REJOIN_WINDOW_MS;
    const entry = (time: number, packageId: string) => ({ time, packageId });
    expect(recentRejoins([
      entry(now - REJOIN_WINDOW_MS, 'old'),
      entry(now - 1, 'b'),
      entry(now - 2, 'a'),
      entry(now - 1, 'a'),
      entry(now + 5, 'future'),
      now - 3,
      null,
    ], now)).toEqual([entry(now - 2, 'a'), entry(now - 1, 'b')]);
    expect(CLIENT_REJOIN_LIMIT).toBe(3);
  });

  it('takes keys from the first verified continuous group on only from groups', () => {
    expect(requiresGroupKey(10, null)).toBe(false);
    expect(requiresGroupKey(9, 10)).toBe(false);
    expect(requiresGroupKey(10, 10)).toBe(true);
    expect(requiresGroupKey(11, 10)).toBe(true);
  });
});
