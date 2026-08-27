import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.JWT_SECRET ||= 'test-jwt-secret-key-at-least-32-bytes';

describe('management security invariants', () => {
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
    assert.doesNotThrow(() => assertValidRolePosition(0));
    assert.doesNotThrow(() => assertValidRolePosition(1_000_000));
    assert.throws(() => assertValidRolePosition(-1), /INVALID_POSITION/);
    assert.throws(() => assertValidRolePosition(1_000_001), /INVALID_POSITION/);
    assert.throws(() => assertValidRolePosition(1.5), /INVALID_POSITION/);
    const { assertValidCategoryPosition } = await import('./channel.service.js');
    assert.doesNotThrow(() => assertValidCategoryPosition(0));
    assert.throws(() => assertValidCategoryPosition(-1), /INVALID_POSITION/);
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

  it('applies role union, category, then channel overrides with allow winning at each level', async () => {
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
      // Same-level allow takes precedence over the deny from another role.
      { roleId: 'role-b', allowMask: Permissions.SEND_MESSAGES, denyMask: 0 },
    ]);
    assert.equal((category.permissionMask & Permissions.SEND_MESSAGES) !== 0, true);
    assert.equal((category.permissionMask & Permissions.ATTACH_FILES) !== 0, true);
    const channel = applyPermissionOverrideLevel(category.permissionMask, [
      { roleId: 'role-a', allowMask: 0, denyMask: Permissions.VIEW_CHANNELS | Permissions.ATTACH_FILES },
      { roleId: 'role-b', allowMask: Permissions.VIEW_CHANNELS, denyMask: 0 },
    ]);
    assert.equal((channel.permissionMask & Permissions.VIEW_CHANNELS) !== 0, true);
    assert.equal((channel.permissionMask & Permissions.ATTACH_FILES) !== 0, false);
    assert.equal((channel.permissionMask & Permissions.MANAGE_CHANNELS) !== 0, true);

    assert.doesNotThrow(() => assertValidChannelOverrideMask(CHANNEL_SCOPED_PERMISSION_MASK));
    assert.throws(() => assertValidChannelOverrideMask(Permissions.MANAGE_CHANNELS), /INVALID_OVERRIDE_PERMISSIONS/);
    assert.throws(() => assertValidChannelOverrideMask(-1), /INVALID_OVERRIDE_PERMISSIONS/);

    const ownerAuthorization = {
      permissions: CHANNEL_SCOPED_PERMISSION_MASK,
      isPrivateMember: false,
    } as any;
    assert.equal(isVisibleChannelAuthorization(ownerAuthorization), false, 'owner still needs explicit private membership');
    assert.equal(isVisibleChannelAuthorization({ ...ownerAuthorization, isPrivateMember: true }), true);
  });
});
