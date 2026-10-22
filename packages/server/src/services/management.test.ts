import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { SQL } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';

describe('management security invariants', () => {
  it('bounds password work and rejects excess queued CPU work', async () => {
    const { runPasswordWork, passwordWorkSnapshot } = await import('../security/password-work.js');
    const releases: Array<() => void> = [];
    const work = Array.from({ length: 18 }, () => runPasswordWork(() => new Promise<void>((resolve) => {
      releases.push(resolve);
    })));
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.deepEqual(passwordWorkSnapshot(), {
      active: 2,
      pending: 16,
      concurrency: 2,
      maxPending: 16,
    });
    await assert.rejects(runPasswordWork(async () => undefined), /AUTH_CAPACITY/);
    while (releases.length > 0 || passwordWorkSnapshot().pending > 0) {
      releases.splice(0).forEach((release) => release());
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    await Promise.all(work);
  });

  it('runs bcrypt compatibility work only in the fixed worker pool', async () => {
    const {
      hashPassword,
      passwordWorkerSnapshot,
      verifyPassword,
    } = await import('../security/password-work.js');
    const hash = await hashPassword('worker-isolated-password', 12);
    assert.match(hash, /^p2:/);
    assert.equal(await verifyPassword('worker-isolated-password', hash), true);
    assert.equal(await verifyPassword('incorrect-password', hash), false);
    await assert.rejects(
      verifyPassword('worker-isolated-password', `$2b$16$${'A'.repeat(53)}`),
      /UNSUPPORTED_PASSWORD_HASH/,
    );
    const snapshot = passwordWorkerSnapshot();
    assert.equal(snapshot.workers >= 1 && snapshot.workers <= 2, true);
    assert.equal(snapshot.threadIds.every((threadId) => threadId > 0), true);
  });

  it('rejects permission masks outside the declared bit set', async () => {
    const {
      ALL_PERMISSION_MASK,
      assertValidPermissionMask,
      assertValidRolePosition,
    } = await import('./role.service.js');
    assert.doesNotThrow(() => assertValidPermissionMask(0));
    assert.doesNotThrow(() => assertValidPermissionMask(ALL_PERMISSION_MASK));
    assert.throws(() => assertValidPermissionMask(-1), /INVALID_PERMISSIONS/);
    assert.throws(() => assertValidPermissionMask(ALL_PERMISSION_MASK + 1), /INVALID_PERMISSIONS/);
    assert.throws(() => assertValidPermissionMask(1.5), /INVALID_PERMISSIONS/);
    for (const value of [2 ** 31, 2 ** 32, 2 ** 32 + 64, 2 ** 40, Number.MAX_SAFE_INTEGER, NaN, Infinity]) {
      assert.throws(() => assertValidPermissionMask(value), /INVALID_PERMISSIONS/);
    }
    assert.doesNotThrow(() => assertValidRolePosition(0));
    assert.doesNotThrow(() => assertValidRolePosition(1_000_000));
    assert.throws(() => assertValidRolePosition(-1), /INVALID_POSITION/);
    assert.throws(() => assertValidRolePosition(1_000_001), /INVALID_POSITION/);
    assert.throws(() => assertValidRolePosition(1.5), /INVALID_POSITION/);
    const { assertValidCategoryPosition } = await import('./channel.service.js');
    assert.doesNotThrow(() => assertValidCategoryPosition(0));
    assert.throws(() => assertValidCategoryPosition(-1), /INVALID_POSITION/);
  });

  it('routes generic attention events only to authorized viewers', async () => {
    const { buildAttentionRecipients } = await import('./message.service.js');
    assert.deepEqual(buildAttentionRecipients(
      ['author', 'mentioned', 'replied', 'broadcast'],
      'workspace-a',
      'author',
      true,
      ['mentioned', 'outsider', 'mentioned'],
      'replied',
    ), [
      { userId: 'broadcast', workspaceId: 'workspace-a', kind: 'mention' },
      { userId: 'mentioned', workspaceId: 'workspace-a', kind: 'mention' },
      { userId: 'replied', workspaceId: 'workspace-a', kind: 'mention' },
      { userId: 'replied', workspaceId: 'workspace-a', kind: 'reply' },
    ]);
  });

  it('normalizes email bindings and hashes invitation tokens without retaining plaintext', async () => {
    const {
      assertValidInvitationLifetime,
      hashInvitationToken,
      normalizeInvitationEmail,
    } = await import('./invitation.service.js');
    const token = 'one-time-token-with-more-than-thirty-two-characters';
    const hash = hashInvitationToken(token);
    assert.equal(normalizeInvitationEmail('  Alice@Example.TEST '), 'alice@example.test');
    assert.match(hash, /^[a-f0-9]{64}$/);
    assert.notEqual(hash, token);
    assert.equal(hashInvitationToken(token), hash);
    assert.notEqual(hashInvitationToken(`${token}-different`), hash);
    assert.doesNotThrow(() => assertValidInvitationLifetime(300));
    assert.doesNotThrow(() => assertValidInvitationLifetime(30 * 24 * 60 * 60));
    assert.throws(() => assertValidInvitationLifetime(299), /INVALID_INVITATION_EXPIRY/);
    assert.throws(() => assertValidInvitationLifetime(1.5), /INVALID_INVITATION_EXPIRY/);
  });

  it('lets an inviter hand out only roles within their own authority', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { mayGrantInvitationRole } = await import('./invitation.service.js');
    const role = (permissions: number, position: number) => ({ permissions, position });
    const inviter = (permissions: number, highestPosition: number) => ({ isOwner: false, permissions, highestPosition });
    const member = role(Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES, 50);
    const guest = role(Permissions.VIEW_CHANNELS, 20);
    const manages = Permissions.MANAGE_MEMBERS | Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES;

    // The owner may hand out any role, named or not.
    assert.equal(mayGrantInvitationRole({ isOwner: true, permissions: 0, highestPosition: -1 }, member, true), true);
    assert.equal(mayGrantInvitationRole({ isOwner: true, permissions: 0, highestPosition: -1 }, member, false), true);

    // Without naming a role, the inviter needs every permission the role carries.
    assert.equal(mayGrantInvitationRole(inviter(manages, 50), member, false), true);
    assert.equal(mayGrantInvitationRole(inviter(manages, 80), role(manages | Permissions.MANAGE_CHANNELS, 50), false), false);
    assert.equal(mayGrantInvitationRole(inviter(Permissions.MANAGE_MEMBERS | Permissions.VIEW_CHANNELS, 80), member, false), false);

    // Naming a role also needs MANAGE_ROLES and a role below the inviter's highest.
    assert.equal(mayGrantInvitationRole(inviter(manages, 80), guest, true), false);
    assert.equal(mayGrantInvitationRole(inviter(manages | Permissions.MANAGE_ROLES, 80), guest, true), true);
    assert.equal(mayGrantInvitationRole(inviter(manages | Permissions.MANAGE_ROLES, 50), member, true), false);
    assert.equal(mayGrantInvitationRole(inviter(manages | Permissions.MANAGE_ROLES, 20), member, true), false);
    assert.equal(mayGrantInvitationRole(inviter(manages | Permissions.MANAGE_ROLES, 80), role(Permissions.VIEW_AUDIT_LOG, 20), true), false);
  });

  it('holds an invitation for a role to the bits its overrides allow, unless it is the default role or the owner invites', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { inviterHoldsRoleOverrides } = await import('./invitation.service.js');
    const world = authorizationSnapshot({
      roles: {
        // The manager may not mention everyone.
        manager: {
          permissions: Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES | Permissions.MANAGE_MEMBERS | Permissions.MANAGE_ROLES,
          position: 60,
        },
        announcer: { permissions: Permissions.VIEW_CHANNELS, position: 40 },
        Member: { permissions: Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES, position: 50 },
      },
      members: { manager: ['manager'] },
      channels: [],
    });
    // Only whether the inviter owns the workspace is read from it.
    const inviter = { isOwner: false, permissions: 0, highestPosition: 60 };
    const row = (allowMask: number, denyMask: number) => ({ allowMask, denyMask });
    const holds = (userId: string, roleName: string, categories: Array<ReturnType<typeof row>>) => inviterHoldsRoleOverrides(
      channellessStore(world, categories), 'workspace-a', userId, inviter, { id: roleName, name: roleName },
    );

    // Handing out a role takes the bits that assigning it takes: those its overrides allow.
    assert.equal(await holds('manager', 'announcer', [row(Permissions.MENTION_EVERYONE, 0)]), false);
    assert.equal(await holds('manager', 'announcer', [row(Permissions.SEND_MESSAGES | Permissions.MENTION_EVERYONE, 0)]), false);
    assert.equal(await holds('manager', 'announcer', [row(Permissions.SEND_MESSAGES, 0)]), true);
    // Restricting people, or having no overrides, takes none.
    assert.equal(await holds('manager', 'announcer', [row(0, Permissions.MENTION_EVERYONE)]), true);
    assert.equal(await holds('manager', 'announcer', []), true);
    // Someone who is not in the workspace holds nothing.
    assert.equal(await holds('stranger', 'announcer', []), false);

    // The default role is what an invitation without a role hands out, whatever its overrides.
    assert.equal(await holds('manager', 'Member', [row(Permissions.MENTION_EVERYONE, 0)]), true);
    // For the default role and for the owner nothing is looked up at all.
    assert.equal(await inviterHoldsRoleOverrides(
      untouchedStore, 'workspace-a', 'manager', inviter, { id: 'Member', name: 'Member' },
    ), true);
    assert.equal(await inviterHoldsRoleOverrides(
      untouchedStore, 'workspace-a', 'owner', { isOwner: true, permissions: 0, highestPosition: -1 }, { id: 'announcer', name: 'announcer' },
    ), true);
  });

  it('asks whether a workspace has room for one more member, and spends an invitation without adding anyone', async () => {
    const { MAX_WORKSPACE_MEMBERS } = await import('@alparts/shared');
    const { assertWorkspaceHasRoom, spendLockedInvitation } = await import('./invitation.service.js');
    const claim = { invitation: { id: 'invitation-a', workspaceId: 'workspace-a' }, role: { id: 'role-a' }, now: new Date(0) } as any;
    const limits: number[] = [];
    const workspaceOfMembers = (count: number) => ({
      query: {
        workspaceMembers: {
          findMany: async ({ limit }: { limit: number }) => {
            limits.push(limit);
            return Array.from({ length: Math.min(count, limit) }, () => ({ id: 'member' }));
          },
        },
      },
    });
    await assertWorkspaceHasRoom(workspaceOfMembers(MAX_WORKSPACE_MEMBERS - 1), claim);
    await assert.rejects(assertWorkspaceHasRoom(workspaceOfMembers(MAX_WORKSPACE_MEMBERS), claim), /WORKSPACE_MEMBER_LIMIT/);
    await assert.rejects(assertWorkspaceHasRoom(workspaceOfMembers(MAX_WORKSPACE_MEMBERS + 100), claim), /WORKSPACE_MEMBER_LIMIT/);
    assert.deepEqual(limits, [MAX_WORKSPACE_MEMBERS + 1, MAX_WORKSPACE_MEMBERS + 1, MAX_WORKSPACE_MEMBERS + 1], 'the count stays bounded');

    // Spending records when and no user, and only while the invitation is still open.
    const updates: Array<Record<string, unknown>> = [];
    const invitationsUpdating = (updated: number) => ({
      update: () => ({
        set: (values: Record<string, unknown>) => {
          updates.push(values);
          return { where: () => ({ returning: async () => Array.from({ length: updated }, () => ({ id: 'invitation-a' })) }) };
        },
      }),
    });
    assert.equal(await spendLockedInvitation(invitationsUpdating(1), claim), 'invitation-a');
    assert.deepEqual(updates, [{ usedAt: claim.now, usedBy: null }]);
    await assert.rejects(spendLockedInvitation(invitationsUpdating(0), claim), /INVALID_INVITATION/);
  });

  it('applies role union, category, then channel overrides with deny winning within each level', async () => {
    const { Permissions } = await import('@alparts/shared');
    const {
      CHANNEL_SCOPED_PERMISSION_MASK,
      applyPermissionOverrideLevel,
      assertValidChannelOverrideMask,
      isVisibleChannelAuthorization,
    } = await import('./authorization.service.js');
    const base = Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES | Permissions.MANAGE_CHANNELS;
    const category = applyPermissionOverrideLevel(base, [
      { roleId: 'role-a', allowMask: Permissions.ATTACH_FILES, denyMask: Permissions.SEND_MESSAGES },
      // Same-level deny survives an allow from another role.
      { roleId: 'role-b', allowMask: Permissions.SEND_MESSAGES, denyMask: 0 },
    ]);
    assert.equal((category.permissionMask & Permissions.SEND_MESSAGES) !== 0, false);
    assert.equal((category.permissionMask & Permissions.ATTACH_FILES) !== 0, true);
    const channel = applyPermissionOverrideLevel(category.permissionMask, [
      { roleId: 'role-a', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS | Permissions.ATTACH_FILES },
      { roleId: 'role-b', allowMask: Permissions.VIEW_CHANNELS, denyMask: 0 },
    ]);
    assert.equal((channel.permissionMask & Permissions.VIEW_CHANNELS) !== 0, false);
    assert.equal((channel.permissionMask & Permissions.ATTACH_FILES) !== 0, false);
    assert.equal((channel.permissionMask & Permissions.MANAGE_CHANNELS) !== 0, true);

    assert.doesNotThrow(() => assertValidChannelOverrideMask(CHANNEL_SCOPED_PERMISSION_MASK));
    assert.throws(() => assertValidChannelOverrideMask(Permissions.MANAGE_CHANNELS), /INVALID_OVERRIDE_PERMISSIONS/);
    assert.throws(() => assertValidChannelOverrideMask(-1), /INVALID_OVERRIDE_PERMISSIONS/);
    for (const value of [2 ** 31, 2 ** 32, 2 ** 32 + Permissions.VIEW_CHANNELS, 2 ** 40, NaN, Infinity]) {
      assert.throws(() => assertValidChannelOverrideMask(value), /INVALID_OVERRIDE_PERMISSIONS/);
    }

    const ownerAuthorization = {
      permissions: CHANNEL_SCOPED_PERMISSION_MASK,
      isPrivateMember: false,
    } as any;
    assert.equal(isVisibleChannelAuthorization(ownerAuthorization), false, 'owner still needs explicit private membership');
    assert.equal(isVisibleChannelAuthorization({ ...ownerAuthorization, isPrivateMember: true }), true);
  });

  it('evaluates a bulk authorization snapshot without applying another role\'s simulated override', async () => {
    const { Permissions } = await import('@alparts/shared');
    const {
      getChannelAuthorizationFromSnapshot,
      isVisibleChannelAuthorization,
    } = await import('./authorization.service.js');
    const channel = {
      id: 'channel-a', workspaceId: 'workspace-a', categoryId: 'category-a', isPrivate: true,
    };
    const snapshot = {
      workspaceId: 'workspace-a',
      ownerId: 'owner',
      channels: [channel],
      channelsById: new Map([[channel.id, channel]]),
      membersByUserId: new Map([['member', { id: 'membership-a', userId: 'member' }]]),
      rolesById: new Map([
        ['role-a', { id: 'role-a', name: 'Member', permissions: Permissions.VIEW_CHANNELS, position: 10 }],
        ['role-b', { id: 'role-b', name: 'Other', permissions: 0, position: 5 }],
      ]),
      roleIdsByUserId: new Map([['member', ['role-a']]]),
      categoryOverridesById: new Map(),
      channelOverridesById: new Map(),
      privateMemberIdsByChannelId: new Map([['channel-a', new Set(['member'])]]),
    };
    const baseline = getChannelAuthorizationFromSnapshot(snapshot, 'member', channel);
    assert.equal(isVisibleChannelAuthorization(baseline), true);
    const simulatedOtherRoleDeny = getChannelAuthorizationFromSnapshot(snapshot, 'member', channel, {
      categoryOverrideMutation: {
        roleId: 'role-b', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS,
      },
    });
    assert.equal(isVisibleChannelAuthorization(simulatedOtherRoleDeny), true);
    const simulatedAssignedRoleDeny = getChannelAuthorizationFromSnapshot(snapshot, 'member', channel, {
      categoryOverrideMutation: {
        roleId: 'role-a', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS,
      },
    });
    assert.equal(isVisibleChannelAuthorization(simulatedAssignedRoleDeny), false);
  });

  it('purges the packages of users who lost access with one statement per table, however many channels changed', async () => {
    const { applyViewerEffectsAndRotation } = await import('./authorization.service.js');
    const uuid = (kind: number, index: number) => `00000000-0000-4000-${kind}000-${index.toString(16).padStart(12, '0')}`;
    const channelIds = Array.from({ length: 300 }, (_, index) => uuid(8, index));
    const [stays, leaves, joins] = [uuid(9, 1), uuid(9, 2), uuid(9, 3)];
    const dialect = new PgDialect();
    const statements: Array<{ sql: string; params: unknown[] }> = [];
    const store = {
      // No channel has key epochs, so only the group bookkeeping runs.
      selectDistinct: () => ({ from: () => ({ where: async () => [] }) }),
      execute: async (query: SQL) => {
        statements.push(dialect.sqlToQuery(query));
        return { rows: [] };
      },
    };
    const access = (viewers: Map<string, string[]>) => ({ viewers, keyRecipients: viewers });
    const before = access(new Map(channelIds.map((channelId) => [channelId, [stays, leaves]])));
    // The first channel only gains a viewer; every other one loses one.
    const after = access(new Map(channelIds.map((channelId, index) => [channelId, index === 0 ? [stays, leaves, joins] : [stays]])));
    assert.equal((await applyViewerEffectsAndRotation(store, before, after)).length, channelIds.length);
    const purges = statements.filter((statement) => /delete from "mls_(member_packages|rejoin_requests)"/.test(statement.sql));
    assert.equal(purges.length, 2, 'purge round trips must not grow with channel count');
    const lost = channelIds.slice(1).flatMap((channelId) => [channelId, leaves]);
    for (const purge of purges) assert.deepEqual(purge.params, lost);
  });

  it('keeps viewers of a voice channel who may not join its call out of its key recipients', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { captureChannelAccessFromSnapshot } = await import('./authorization.service.js');
    const access = captureChannelAccessFromSnapshot(callSnapshot(Permissions));
    assert.deepEqual(access.viewers.get('voice'), ['caller', 'listener', 'owner']);
    assert.deepEqual(access.keyRecipients.get('voice'), ['caller', 'owner']);
    assert.deepEqual(access.viewers.get('text'), ['caller', 'listener', 'owner']);
    assert.deepEqual(access.keyRecipients.get('text'), ['caller', 'listener', 'owner']);
  });

  it('removes a viewer from a voice channel\'s call when CONNECT_VOICE is revoked, without touching key state', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { applyViewerEffectsAndRotation, captureChannelAccessFromSnapshot } = await import('./authorization.service.js');
    const deny = [{ roleId: 'speaker', allowMask: 0, denyMask: Permissions.CONNECT_VOICE }];
    const revocations = {
      'role edit': callSnapshot(Permissions, { speakerPermissions: 0 }),
      'role unassignment': callSnapshot(Permissions, { callerRoles: ['guest'] }),
      'channel override': callSnapshot(Permissions, { channelOverrides: { voice: deny } }),
      'category override': callSnapshot(Permissions, { categoryOverrides: deny }),
    };
    const before = captureChannelAccessFromSnapshot(callSnapshot(Permissions));
    for (const [path, revoked] of Object.entries(revocations)) {
      const after = captureChannelAccessFromSnapshot(revoked);
      assert.deepEqual(after.viewers, before.viewers, `${path} keeps every viewer`);
      assert.deepEqual(await applyViewerEffectsAndRotation(untouchedStore, before, after), [{
        channelId: 'voice', lostUserIds: [], gainedUserIds: [], lostCallUserIds: ['caller'], rotationRequired: false,
      }], path);
      assert.deepEqual(await applyViewerEffectsAndRotation(untouchedStore, after, before), [], `${path} restored`);
    }

    // Losing the channel itself is a viewer loss, not a second call loss.
    const hidden = captureChannelAccessFromSnapshot(callSnapshot(Permissions, {
      channelOverrides: { voice: [{ roleId: 'guest', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS }] },
    }));
    assert.deepEqual(await applyViewerEffectsAndRotation(keylessStore, before, hidden), [{
      channelId: 'voice', lostUserIds: ['caller', 'listener'], gainedUserIds: [], lostCallUserIds: [], rotationRequired: false,
    }]);
  });

  it('protects and revokes a voice channel viewer who may not join its call like any viewer (GHSA-3xrh-c9vq-jh4j)', async () => {
    const { Permissions } = await import('@alparts/shared');
    const {
      applyViewerEffectsAndRotation,
      assertNoSuperiorAccessLoss,
      captureChannelAccessFromSnapshot,
    } = await import('./authorization.service.js');
    const roles = {
      'security-manager': { permissions: Permissions.VIEW_CHANNELS | Permissions.VIEW_AUDIT_LOG | Permissions.MANAGE_MEMBERS, position: 80 },
      'channel-manager': {
        permissions: Permissions.VIEW_CHANNELS | Permissions.MANAGE_CHANNELS | Permissions.CONNECT_VOICE,
        position: 60,
      },
    };
    const members = { auditor: ['security-manager'], manager: ['channel-manager'] };
    const shared = authorizationSnapshot({
      roles, members, channels: [{ id: 'voice', type: 'voice', isPrivate: true }],
      privateMembers: { voice: ['auditor', 'manager'] },
    });
    const managerOnly = authorizationSnapshot({
      roles, members, channels: [{ id: 'voice', type: 'voice', isPrivate: true }],
      privateMembers: { voice: ['manager'] },
    });
    const publicVoice = authorizationSnapshot({ roles, members, channels: [{ id: 'voice', type: 'voice' }] });
    assert.throws(() => assertNoSuperiorAccessLoss(shared, managerOnly, 'manager'), /MEMBER_HIERARCHY/);
    assert.throws(() => assertNoSuperiorAccessLoss(publicVoice, managerOnly, 'manager'), /MEMBER_HIERARCHY/);
    assert.doesNotThrow(() => assertNoSuperiorAccessLoss(shared, managerOnly, 'owner'));
    // When the owner removes the auditor, the auditor's sockets leave the channel's rooms.
    assert.deepEqual(await applyViewerEffectsAndRotation(
      keylessStore,
      captureChannelAccessFromSnapshot(shared),
      captureChannelAccessFromSnapshot(managerOnly),
    ), [{ channelId: 'voice', lostUserIds: ['auditor'], gainedUserIds: [], lostCallUserIds: [], rotationRequired: false }]);
  });

  it('holds a category change to the authority the override API demands for the overrides it swaps', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { assertCategoryChangeAuthority } = await import('./permission-override.service.js');
    const snapshot = authorizationSnapshot({
      roles: {
        staff: { permissions: Permissions.VIEW_CHANNELS, position: 90 },
        // The manager may not mention everyone.
        manager: { permissions: Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES | Permissions.MANAGE_CHANNELS, position: 60 },
        announcer: { permissions: Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES, position: 40 },
      },
      members: { manager: ['manager', 'announcer'] },
      channels: [],
    });
    const row = (roleId: string, allowMask: number, denyMask: number) => ({ roleId, allowMask, denyMask });
    const change = (from: OverrideValue[], to: OverrideValue[], actor = 'manager') => () => assertCategoryChangeAuthority(snapshot, actor, from, to);

    // Entering a category applies an allow the manager lacks.
    assert.throws(change([], [row('announcer', Permissions.MENTION_EVERYONE, 0)]), /NOT_AUTHORIZED/);
    // Leaving one drops a deny on the manager's own role, or on a role above it.
    assert.throws(change([row('manager', 0, Permissions.SEND_MESSAGES)], []), /NOT_AUTHORIZED/);
    assert.throws(change([row('staff', 0, Permissions.VIEW_CHANNELS)], []), /NOT_AUTHORIZED/);
    // Changing a row counts the bits of both versions, and a deny counts like an allow.
    assert.throws(change(
      [row('announcer', Permissions.SEND_MESSAGES, 0)],
      [row('announcer', Permissions.SEND_MESSAGES, Permissions.MENTION_EVERYONE)],
    ), /NOT_AUTHORIZED/);
    assert.throws(change([], [row('announcer', 0, Permissions.ATTACH_FILES)]), /NOT_AUTHORIZED/);
    // A role the snapshot does not know cannot be shown to rank below the manager.
    assert.throws(change([row('missing', 0, Permissions.SEND_MESSAGES)], []), /NOT_AUTHORIZED/);

    // A lower role and bits the manager holds, either way.
    assert.doesNotThrow(change([], [row('announcer', 0, Permissions.SEND_MESSAGES)]));
    assert.doesNotThrow(change([row('announcer', Permissions.SEND_MESSAGES, 0)], []));
    // The same override on both sides changes nothing, whatever the role.
    assert.doesNotThrow(change(
      [row('staff', Permissions.MENTION_EVERYONE, 0), row('announcer', 0, Permissions.SEND_MESSAGES)],
      [row('announcer', 0, Permissions.SEND_MESSAGES), row('staff', Permissions.MENTION_EVERYONE, 0)],
    ));
    assert.doesNotThrow(change([row('staff', 0, 0)], []));
    assert.doesNotThrow(change([], []));

    // The owner keeps full power; a non-member has none.
    const ownerSnapshot = authorizationSnapshot({ roles: { announcer: { permissions: 0, position: 1 } }, members: {}, channels: [] });
    const ownerChange = (from: OverrideValue[], to: OverrideValue[]) => () => assertCategoryChangeAuthority(ownerSnapshot, 'owner', from, to);
    assert.doesNotThrow(ownerChange([row('announcer', Permissions.MENTION_EVERYONE, Permissions.VIEW_CHANNELS)], []));
    assert.doesNotThrow(ownerChange([], [row('announcer', Permissions.MENTION_EVERYONE, 0)]));
    assert.throws(change([row('announcer', 0, Permissions.SEND_MESSAGES)], [], 'stranger'), /NOT_AUTHORIZED/);
  });

  it('holds assigning or removing a role to the bits its category and channel overrides touch', async () => {
    const { Permissions } = await import('@alparts/shared');
    const { assertRoleOverridesHeld } = await import('./role.service.js');
    const snapshot = authorizationSnapshot({
      roles: {
        manager: { permissions: Permissions.VIEW_CHANNELS | Permissions.SEND_MESSAGES | Permissions.MANAGE_ROLES, position: 60 },
        // The manager holds this role too, and #quiet denies it SEND_MESSAGES.
        muted: { permissions: 0, position: 20 },
      },
      members: { manager: ['manager', 'muted'], other: ['manager'] },
      channels: [{ id: 'open', type: 'text' }, { id: 'quiet', type: 'text' }],
      channelOverrides: { quiet: [{ roleId: 'muted', allowMask: 0, denyMask: Permissions.SEND_MESSAGES }] },
    });
    const none: Parameters<typeof assertRoleOverridesHeld>[2] = { categories: [], channels: [] };
    const category = (allowMask: number, denyMask: number) => ({ ...none, categories: [{ allowMask, denyMask }] });
    const channel = (channelId: string, allowMask: number, denyMask: number) => ({ ...none, channels: [{ channelId, allowMask, denyMask }] });
    const assign = (overrides: typeof none, actor = 'manager') => () => assertRoleOverridesHeld(snapshot, actor, overrides, 'assign');
    const unassign = (overrides: typeof none, actor = 'manager') => () => assertRoleOverridesHeld(snapshot, actor, overrides, 'unassign');

    // Assigning grants what the overrides allow: never a bit the manager lacks.
    assert.throws(assign(category(Permissions.MENTION_EVERYONE, 0)), /PERMISSION_ESCALATION/);
    assert.throws(assign(channel('open', Permissions.MENTION_EVERYONE, 0)), /PERMISSION_ESCALATION/);
    // In a channel, the bits the manager holds there, not only in the workspace.
    assert.throws(assign(channel('quiet', Permissions.SEND_MESSAGES, 0)), /PERMISSION_ESCALATION/);
    assert.doesNotThrow(assign(channel('open', Permissions.SEND_MESSAGES, 0)));
    assert.doesNotThrow(assign(category(Permissions.SEND_MESSAGES, 0)));
    // Restricting someone needs no bit of the manager's.
    assert.doesNotThrow(assign(category(0, Permissions.MENTION_EVERYONE)));
    assert.doesNotThrow(assign(channel('open', 0, Permissions.MENTION_EVERYONE)));
    assert.doesNotThrow(assign(none));

    // Removing lifts what the overrides deny: never one the manager could not write.
    assert.throws(unassign(category(0, Permissions.MENTION_EVERYONE)), /PERMISSION_ESCALATION/);
    assert.throws(unassign(channel('open', 0, Permissions.MENTION_EVERYONE)), /PERMISSION_ESCALATION/);
    // A manager held back in a channel by a role cannot lift that by dropping the role.
    assert.throws(unassign(channel('quiet', 0, Permissions.SEND_MESSAGES)), /PERMISSION_ESCALATION/);
    assert.doesNotThrow(unassign(channel('open', 0, Permissions.SEND_MESSAGES)));
    assert.doesNotThrow(unassign(category(0, Permissions.SEND_MESSAGES)));
    // Taking away what was allowed grants nothing.
    assert.doesNotThrow(unassign(category(Permissions.MENTION_EVERYONE, 0)));
    assert.doesNotThrow(unassign(channel('open', Permissions.MENTION_EVERYONE, 0)));

    // The owner may give or take any role; a stranger may not.
    assert.doesNotThrow(assign(category(Permissions.MENTION_EVERYONE, 0), 'owner'));
    assert.doesNotThrow(unassign(channel('quiet', 0, Permissions.SEND_MESSAGES), 'owner'));
    assert.throws(assign(none, 'stranger'), /NOT_AUTHORIZED/);
  });

  it('names to an actor only the channels it sees, and only counts the others, direct messages included (GHSA-6q58)', async () => {
    const { Permissions } = await import('@alparts/shared');
    const {
      applyViewerEffectsAndRotation,
      captureChannelAccessFromSnapshot,
      limitEffectsToChannels,
      visibleChannelIdsFromSnapshot,
    } = await import('./authorization.service.js');
    const world = (memberPermissions: number, channelOverrides: Record<string, OverrideValue[]> = {}) => authorizationSnapshot({
      roles: {
        manager: { permissions: Permissions.VIEW_CHANNELS | Permissions.MANAGE_ROLES, position: 60 },
        member: { permissions: memberPermissions, position: 50 },
      },
      members: { manager: ['manager'], alice: ['member'], bob: ['member'], carol: ['member'] },
      channels: [
        { id: 'public', type: 'text' },
        { id: 'mine', type: 'text', isPrivate: true },
        { id: 'theirs', type: 'text', isPrivate: true },
        { id: 'dm', type: 'dm', isPrivate: true },
      ],
      privateMembers: { mine: ['manager', 'alice'], theirs: ['bob'], dm: ['alice', 'carol'] },
      channelOverrides,
    });
    const before = world(Permissions.VIEW_CHANNELS);
    const after = world(0);
    const effects = await applyViewerEffectsAndRotation(
      keylessStore,
      captureChannelAccessFromSnapshot(before),
      captureChannelAccessFromSnapshot(after),
    );
    // The change takes every channel from the members, the other people's private channel and the DM included.
    assert.deepEqual(
      effects.map((effect) => [effect.channelId, effect.lostUserIds]),
      [['dm', ['alice', 'carol']], ['mine', ['alice']], ['public', ['alice', 'bob', 'carol']], ['theirs', ['bob']]],
    );
    const shown = limitEffectsToChannels(effects, visibleChannelIdsFromSnapshot(
      after, 'manager', effects.map((effect) => effect.channelId),
    ));
    assert.deepEqual(shown.roomEffects.map((effect) => effect.channelId), ['mine', 'public']);
    assert.equal(shown.otherChannelCount, 2);
    assert.equal(JSON.stringify(shown).includes('theirs'), false);
    assert.equal(JSON.stringify(shown).includes('dm'), false);
    assert.equal(JSON.stringify(shown).includes('carol'), true, 'carol loses #public, which the manager sees');

    // What counts is the view after the change: a channel the change hides from the actor is not named either.
    const hidesFromManager = world(Permissions.VIEW_CHANNELS, {
      public: [{ roleId: 'manager', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS }],
    });
    assert.deepEqual([...visibleChannelIdsFromSnapshot(before, 'manager', ['public'])], ['public']);
    assert.deepEqual([...visibleChannelIdsFromSnapshot(hidesFromManager, 'manager', ['public'])], []);
    // The owner is in none of the private channels, so it is told of #public only.
    assert.deepEqual(
      [...visibleChannelIdsFromSnapshot(after, 'owner', ['dm', 'mine', 'public', 'theirs'])],
      ['public'],
    );
    assert.deepEqual(limitEffectsToChannels([], new Set()), { roomEffects: [], otherChannelCount: 0 });
  });
});

type OverrideValue = { roleId: string; allowMask: number; denyMask: number };

/** An in-memory workspace snapshot whose channels all sit in one category; the owner holds no role. */
function authorizationSnapshot(input: {
  roles: Record<string, { permissions: number; position: number }>;
  members: Record<string, string[]>;
  channels: Array<{ id: string; type: string; isPrivate?: boolean }>;
  categoryOverrides?: OverrideValue[];
  channelOverrides?: Record<string, OverrideValue[]>;
  privateMembers?: Record<string, string[]>;
}) {
  const channels = input.channels.map((channel) => ({
    id: channel.id, workspaceId: 'workspace-a', categoryId: 'category-a', isPrivate: channel.isPrivate ?? false, type: channel.type,
  }));
  return {
    workspaceId: 'workspace-a',
    ownerId: 'owner',
    channels,
    channelsById: new Map(channels.map((channel) => [channel.id, channel])),
    membersByUserId: new Map(['owner', ...Object.keys(input.members)].map((userId) => [userId, { id: `membership-${userId}`, userId }])),
    rolesById: new Map(Object.entries(input.roles).map(([id, role]) => [id, { id, name: id, ...role }])),
    roleIdsByUserId: new Map<string, string[]>([['owner', []], ...Object.entries(input.members)]),
    categoryOverridesById: new Map<string, OverrideValue[]>(input.categoryOverrides ? [['category-a', input.categoryOverrides]] : []),
    channelOverridesById: new Map<string, OverrideValue[]>(Object.entries(input.channelOverrides ?? {})),
    privateMemberIdsByChannelId: new Map<string, Set<string>>(
      Object.entries(input.privateMembers ?? {}).map(([channelId, userIds]) => [channelId, new Set(userIds)]),
    ),
  };
}

/**
 * The reads behind the authorization snapshot of a workspace without channels
 * and behind the category overrides written for one role. A table answers with
 * all its rows whatever the filter, which holds while no channel exists.
 */
function channellessStore(world: ReturnType<typeof authorizationSnapshot>, categoryOverrides: Array<{ allowMask: number; denyMask: number }>) {
  const table = (rows: unknown[]) => ({ findFirst: async () => rows[0], findMany: async () => rows });
  return {
    query: {
      workspaces: table([{ ownerId: world.ownerId }]),
      channels: table([]),
      workspaceMembers: table([...world.membersByUserId.values()]),
      roles: table([...world.rolesById.values()]),
      memberRoles: table([...world.roleIdsByUserId].flatMap(([userId, roleIds]) => roleIds.map((roleId) => ({
        memberId: world.membersByUserId.get(userId)!.id, roleId,
      })))),
      categoryRolePermissionOverrides: table(categoryOverrides),
      channelRolePermissionOverrides: table([]),
    },
  };
}

/** A listener sees the channels; a caller also holds CONNECT_VOICE through the speaker role. */
function callSnapshot(
  permissions: typeof import('@alparts/shared').Permissions,
  change: {
    speakerPermissions?: number;
    callerRoles?: string[];
    categoryOverrides?: OverrideValue[];
    channelOverrides?: Record<string, OverrideValue[]>;
  } = {},
) {
  return authorizationSnapshot({
    roles: {
      guest: { permissions: permissions.VIEW_CHANNELS, position: 5 },
      speaker: { permissions: change.speakerPermissions ?? permissions.CONNECT_VOICE, position: 6 },
    },
    members: { caller: change.callerRoles ?? ['guest', 'speaker'], listener: ['guest'] },
    channels: [{ id: 'voice', type: 'voice' }, { id: 'text', type: 'text' }],
    categoryOverrides: change.categoryOverrides,
    channelOverrides: change.channelOverrides,
  });
}

/** Fails on any read or write: a change that only ends calls leaves key state alone. */
const untouchedStore = new Proxy({}, {
  get: (_target, key) => { throw new Error(`key state touched: ${String(key)}`); },
});

/** Channels without keys or groups: every key-state read finds nothing. */
const keylessStore = {
  selectDistinct: () => ({ from: () => ({ where: async () => [] }) }),
  select: () => ({ from: () => ({ where: async () => [] }) }),
  execute: async () => ({ rows: [] }),
};
