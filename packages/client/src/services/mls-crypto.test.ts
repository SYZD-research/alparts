import { describe, it, expect } from 'vitest';
import { mlsGroupId } from '@alparts/shared';
import {
  addablePackages,
  assertChannelGroup,
  commitChannelGroup,
  createChannelGroup,
  createEpochGroup,
  decodeChannelCommit,
  decodeChannelGroupState,
  encodeChannelGroupState,
  exportChannelKey,
  generateEpochKeyPackage,
  generateMemberPackage,
  groupLeaves,
  joinChannelGroup,
  joinEpochGroup,
  processChannelCommit,
  readMemberPackage,
  treeAuthMap,
} from './mls-crypto';
describe('MLS epoch groups', () => {
  it('agrees on the exporter, binds the group, and excludes old packages after fresh key updates', async () => {
    const alice = await generateEpochKeyPackage('alice');
    const bob = await generateEpochKeyPackage('bob');
    const roster = [alice.publicPackage, bob.publicPackage];
    const first = await createEpochGroup('channel:1:genesis', alice, roster);
    expect(await joinEpochGroup('channel:1:genesis', bob, roster, first.welcome)).toEqual(
      first.raw,
    );
    await expect(joinEpochGroup('other-channel', bob, roster, first.welcome)).rejects.toThrow();
    await expect(
      joinEpochGroup('channel:1:genesis', bob, [bob.publicPackage], first.welcome),
    ).rejects.toThrow();
    const freshAlice = await generateEpochKeyPackage('alice');
    const freshBob = await generateEpochKeyPackage('bob');
    const freshRoster = [freshAlice.publicPackage, freshBob.publicPackage];
    const second = await createEpochGroup('channel:2:parent-transcript', freshAlice, freshRoster);
    expect(
      await joinEpochGroup('channel:2:parent-transcript', freshBob, freshRoster, second.welcome),
    ).toEqual(second.raw);
    expect(second.raw).not.toEqual(first.raw);
    await expect(
      joinEpochGroup('channel:2:parent-transcript', bob, freshRoster, second.welcome),
    ).rejects.toThrow();
    const soloAlice = await generateEpochKeyPackage('alice');
    const solo = await createEpochGroup('channel:3:parent-transcript', soloAlice, [
      soloAlice.publicPackage,
    ]);
    expect(solo.raw.length).toBe(32);
  });
});

describe('continuous channel groups', () => {
  const groupId = mlsGroupId('11111111-1111-4111-8111-111111111111', 3);
  const keys = (pkg: string) => readMemberPackage(pkg);
  const authOf = (entries: Record<string, string>) => new Map(
    Object.entries(entries).map(([id, pkg]) => [id, keys(pkg).signatureKey]),
  );

  it('creates, adds, removes and refreshes with one exporter per version', async () => {
    const alice = await generateMemberPackage('alice');
    const bob = await generateMemberPackage('bob');
    const carol = await generateMemberPackage('carol');
    const auth = authOf({ alice: alice.publicPackage, bob: bob.publicPackage });
    const genesis = await createChannelGroup(groupId, alice, [bob.publicPackage], auth);
    expect(decodeChannelCommit(genesis.commit)).toMatchObject({ epoch: 0, senderLeafIndex: 0, addPackages: [bob.publicPackage] });
    let a = genesis.newState;
    let b = await joinChannelGroup(genesis.welcome, bob, auth);
    assertChannelGroup(b, groupId, 1);
    expect(await exportChannelKey(b, groupId, 3)).toEqual(await exportChannelKey(a, groupId, 3));
    expect(await exportChannelKey(a, groupId, 3)).not.toEqual(await exportChannelKey(a, groupId, 4));

    // Add carol (no path), then remove bob (path), then an empty refresh.
    const addAuth = new Map([...treeAuthMap(a), ['carol', keys(carol.publicPackage).signatureKey]]);
    const add = await commitChannelGroup(a, { add: [carol.publicPackage], removeLeaves: [], authMap: addAuth });
    const addDecoded = decodeChannelCommit(add.commit);
    expect(addDecoded).toMatchObject({ epoch: 1, hasPath: false, removedLeaves: [] });
    b = (await processChannelCommit(b, add.commit, addDecoded, addAuth)).newState;
    a = add.newState;
    let c = await joinChannelGroup(add.welcome, carol, addAuth);
    expect(groupLeaves(c).map((leaf) => leaf.deviceId)).toEqual(['alice', 'bob', 'carol']);

    const removeAuth = treeAuthMap(a, [1]);
    const remove = await commitChannelGroup(a, { add: [], removeLeaves: [1], authMap: removeAuth });
    const removeDecoded = decodeChannelCommit(remove.commit);
    expect(removeDecoded).toMatchObject({ hasPath: true, removedLeaves: [1] });
    // The removed device's callback refuses its own removal.
    await expect(processChannelCommit(b, remove.commit, removeDecoded, removeAuth)).rejects.toThrow();
    c = (await processChannelCommit(c, remove.commit, removeDecoded, removeAuth)).newState;
    a = remove.newState;
    expect(await exportChannelKey(c, groupId, 5)).toEqual(await exportChannelKey(a, groupId, 5));

    const refresh = await commitChannelGroup(c, { add: [], removeLeaves: [], authMap: treeAuthMap(c) });
    const refreshed = await processChannelCommit(
      decodeChannelGroupState(encodeChannelGroupState(a)),
      refresh.commit,
      decodeChannelCommit(refresh.commit),
      treeAuthMap(a),
    );
    a = refreshed.newState;
    // The secrets processed from are handed back to be erased; the new state does not need them.
    expect(refreshed.consumed.length).toBeGreaterThan(0);
    refreshed.consumed.forEach((bytes) => bytes.fill(0));
    expect(await exportChannelKey(a, groupId, 6)).toEqual(await exportChannelKey(refresh.newState, groupId, 6));
    expect(a.historicalReceiverData.size).toBeLessThanOrEqual(1);
  });

  it('skips packages whose keys are already in the tree or whose lifetime has not begun', async () => {
    const alice = await generateMemberPackage('alice');
    const bob = await generateMemberPackage('bob');
    const solo = await createChannelGroup(groupId, alice, [], authOf({ alice: alice.publicPackage }));
    expect(decodeChannelCommit(solo.commit).hasPath).toBe(true);
    expect(solo.welcome).toBe('');
    expect(addablePackages(solo.newState, [bob.publicPackage, alice.publicPackage, bob.publicPackage])).toEqual([bob.publicPackage]);
    const early = Date.now() - 30 * 60_000;
    expect(addablePackages(solo.newState, [bob.publicPackage], early)).toEqual([]);
  });
});
