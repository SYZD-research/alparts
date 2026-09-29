import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
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
});
