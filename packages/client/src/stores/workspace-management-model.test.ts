import { describe, expect, it } from 'vitest';
import {
  invitationStatusAt,
  managementErrorMessage,
  permissionMaskFromNames,
  permissionNamesFromMask,
  roleProtection,
  roleMutationFailurePlan,
  summarizeRolePreview,
} from './workspace-management-model';

describe('workspace management model', () => {
  it('round-trips selected permissions without granting unknown values', () => {
    const mask = permissionMaskFromNames(['VIEW_CHANNELS', 'MANAGE_MEMBERS', 'UNKNOWN']);
    expect(permissionNamesFromMask(mask)).toEqual(['VIEW_CHANNELS', 'MANAGE_MEMBERS']);
  });

  it('derives invitation state deterministically', () => {
    const base = { usedAt: null, revokedAt: null, expiresAt: '2026-01-02T00:00:00.000Z' };
    expect(invitationStatusAt(base, Date.parse('2026-01-01T00:00:00.000Z'))).toBe('active');
    expect(invitationStatusAt(base, Date.parse('2026-01-03T00:00:00.000Z'))).toBe('expired');
    expect(invitationStatusAt({ ...base, revokedAt: '2026-01-01T12:00:00.000Z' }, 0)).toBe('revoked');
    expect(invitationStatusAt({ ...base, usedAt: '2026-01-01T12:00:00.000Z', revokedAt: '2026-01-01T13:00:00.000Z' }, 0)).toBe('used');
  });

  it('protects Owner more strongly than other standard roles', () => {
    expect(roleProtection({ name: 'Owner', standard: true })).toBe('owner');
    expect(roleProtection({ name: 'Member', standard: true })).toBe('standard');
    expect(roleProtection({ name: 'Support', standard: false })).toBeNull();
  });

  it('summarizes preview impact for the confirmation UI', () => {
    const summary = summarizeRolePreview({
      workspaceId: 'workspace',
      operation: 'role.update',
      authorizationRevision: 'a'.repeat(64),
      affectedMembers: [{
        userId: 'user',
        before: {} as never,
        after: {} as never,
        gained: ['SEND_MESSAGES'],
        lost: ['VIEW_CHANNELS', 'ATTACH_FILES'],
      }],
      affectedUserIds: ['user'],
      lostAccessUserIds: ['user'],
      gainedAccessUserIds: [],
      requiresKeyRotation: true,
    });
    expect(summary).toEqual({
      affectedUsers: 1,
      gainedPermissions: 1,
      lostPermissions: 2,
      lostAccessUsers: 1,
      gainedAccessUsers: 0,
      requiresKeyRotation: true,
    });
  });

  it('explains hierarchy and invariant failures without trusting server prose', () => {
    expect(managementErrorMessage({ status: 403 }, 'fallback')).toContain('階層');
    expect(managementErrorMessage({ status: 409 }, 'fallback')).toContain('標準ロール');
  });

  it('discards and refreshes only a stale authorization preview', () => {
    const stale = { status: 409, code: 'STALE_PREVIEW' };
    expect(roleMutationFailurePlan(stale)).toEqual({ discardPreview: true, refreshPreview: true });
    expect(managementErrorMessage(stale, 'fallback')).toContain('再計算');
    expect(roleMutationFailurePlan({ status: 409, code: 'ROLE_CONFLICT' }))
      .toEqual({ discardPreview: true, refreshPreview: false });
  });
});
