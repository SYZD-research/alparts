import { describe, expect, it } from 'vitest';
import { Permissions } from '@alparts/shared';
import type { PermissionOverridePreview } from '../services/api';
import {
  channelScopedPermissionMask,
  formatChannelPermissionReason,
  overrideDeleteInputFromPreview,
  overrideMutationFailurePlan,
  permissionOverridePreviewMatches,
  overridePermissionState,
  overrideWriteInputFromPreview,
  setOverridePermissionState,
  summarizeOverridePreview,
  validateOverrideMasks,
} from './permission-override-model';

describe('permission override model', () => {
  it('keeps allow/deny/inherit mutually exclusive and rejects out-of-scope bits', () => {
    let masks = setOverridePermissionState(0, 0, Permissions.VIEW_CHANNELS, 'deny');
    expect(overridePermissionState(masks.allowMask, masks.denyMask, Permissions.VIEW_CHANNELS)).toBe('deny');
    masks = setOverridePermissionState(masks.allowMask, masks.denyMask, Permissions.VIEW_CHANNELS, 'allow');
    expect(masks).toEqual({ allowMask: Permissions.VIEW_CHANNELS, denyMask: 0 });
    expect(validateOverrideMasks(Permissions.VIEW_CHANNELS, Permissions.VIEW_CHANNELS)).toContain('両方');
    expect(validateOverrideMasks(channelScopedPermissionMask | Permissions.MANAGE_ROLES, 0)).toContain('スコープ外');
  });

  it('copies both preview revisions exactly into write and delete bodies', () => {
    const preview = previewFixture();
    expect(overrideWriteInputFromPreview(preview, Permissions.SEND_MESSAGES, Permissions.ATTACH_FILES)).toEqual({
      allowMask: Permissions.SEND_MESSAGES,
      denyMask: Permissions.ATTACH_FILES,
      expectedRevision: 4,
      expectedAuthorizationRevision: 'b'.repeat(64),
    });
    expect(overrideDeleteInputFromPreview(preview)).toEqual({
      expectedRevision: 4,
      expectedAuthorizationRevision: 'b'.repeat(64),
    });
  });

  it('summarizes viewer effects without double-counting users or channels', () => {
    const preview = previewFixture();
    preview.roomEffects = [
      { channelId: 'channel-1', lostUserIds: ['a', 'b'], gainedUserIds: [], rotationRequired: true },
      { channelId: 'channel-2', lostUserIds: ['b'], gainedUserIds: ['c'], rotationRequired: true },
    ];
    expect(summarizeOverridePreview(preview)).toEqual({
      affectedChannels: 2,
      losingUsers: 2,
      gainingUsers: 1,
      rotationChannels: 2,
    });
  });

  it('discards every failed preview and refreshes only recognized stale conflicts', () => {
    expect(overrideMutationFailurePlan({ status: 409, code: 'STALE_PREVIEW' }))
      .toEqual({ discardPreview: true, refreshPreview: true });
    expect(overrideMutationFailurePlan({ status: 409, code: 'STALE_OVERRIDE' }))
      .toEqual({ discardPreview: true, refreshPreview: true });
    expect(overrideMutationFailurePlan({ status: 409, code: 'OTHER' }))
      .toEqual({ discardPreview: true, refreshPreview: false });
  });

  it('rejects a refreshed preview for a different authorization context', () => {
    const preview = previewFixture();
    expect(permissionOverridePreviewMatches(preview, {
      target: 'channel',
      workspaceId: 'workspace',
      targetId: 'channel',
      roleId: 'role',
      operation: 'delete',
    })).toBe(true);
    expect(permissionOverridePreviewMatches(preview, {
      target: 'category',
      workspaceId: 'workspace',
      targetId: 'channel',
      roleId: 'role',
      operation: 'delete',
    })).toBe(false);
  });

  it('formats only known effective-reason fields and hides unknown payloads', () => {
    const roles = new Map([['role-1', 'Members']]);
    expect(formatChannelPermissionReason({ source: 'channel', effect: 'deny', roleId: 'role-1' }, roles))
      .toContain('Members');
    expect(formatChannelPermissionReason({ source: 'future', secret: 'do-not-render' } as never, roles))
      .toBe('詳細を表示できないサーバー判定');
  });
});

function previewFixture(): PermissionOverridePreview {
  return {
    target: 'channel',
    workspaceId: 'workspace',
    targetId: 'channel',
    roleId: 'role',
    operation: 'delete',
    currentRevision: 4,
    authorizationRevision: 'b'.repeat(64),
    before: null,
    after: null,
    roomEffects: [],
  };
}
