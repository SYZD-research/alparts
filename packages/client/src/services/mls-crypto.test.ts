import { describe, it, expect } from 'vitest';
import { createEpochGroup, generateEpochKeyPackage, joinEpochGroup } from './mls-crypto';
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
