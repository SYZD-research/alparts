import { Permissions, type Permission } from '@alparts/shared';
import type {
  ChannelPermissionReason,
  PermissionOverrideDeleteInput,
  PermissionOverridePreview,
  PermissionOverrideWriteInput,
} from '../services/api';

export type OverridePermissionState = 'inherit' | 'allow' | 'deny' | 'conflict';

export const channelScopedPermissions: Array<{ name: Permission; value: number }> = [
  { name: 'VIEW_CHANNELS', value: Permissions.VIEW_CHANNELS },
  { name: 'SEND_MESSAGES', value: Permissions.SEND_MESSAGES },
  { name: 'EDIT_MESSAGES', value: Permissions.EDIT_MESSAGES },
  { name: 'DELETE_MESSAGES', value: Permissions.DELETE_MESSAGES },
  { name: 'ADD_REACTIONS', value: Permissions.ADD_REACTIONS },
  { name: 'MENTION_EVERYONE', value: Permissions.MENTION_EVERYONE },
  { name: 'PIN_MESSAGES', value: Permissions.PIN_MESSAGES },
  { name: 'ATTACH_FILES', value: Permissions.ATTACH_FILES },
];

export const channelScopedPermissionMask = channelScopedPermissions
  .reduce((mask, permission) => mask | permission.value, 0);

export function overridePermissionState(
  allowMask: number,
  denyMask: number,
  permission: number,
): OverridePermissionState {
  const allowed = (allowMask & permission) === permission;
  const denied = (denyMask & permission) === permission;
  if (allowed && denied) return 'conflict';
  if (allowed) return 'allow';
  if (denied) return 'deny';
  return 'inherit';
}

export function setOverridePermissionState(
  allowMask: number,
  denyMask: number,
  permission: number,
  state: Exclude<OverridePermissionState, 'conflict'>,
): { allowMask: number; denyMask: number } {
  if ((permission & channelScopedPermissionMask) !== permission || permission <= 0) {
    throw new Error('チャンネルスコープ外の権限はoverrideできません');
  }
  const clearedAllow = allowMask & ~permission;
  const clearedDeny = denyMask & ~permission;
  if (state === 'allow') return { allowMask: clearedAllow | permission, denyMask: clearedDeny };
  if (state === 'deny') return { allowMask: clearedAllow, denyMask: clearedDeny | permission };
  return { allowMask: clearedAllow, denyMask: clearedDeny };
}

export function validateOverrideMasks(allowMask: number, denyMask: number): string | null {
  if (
    !Number.isSafeInteger(allowMask)
    || !Number.isSafeInteger(denyMask)
    || allowMask < 0
    || denyMask < 0
    || (allowMask & ~channelScopedPermissionMask) !== 0
    || (denyMask & ~channelScopedPermissionMask) !== 0
  ) return 'この画面では変更できない権限が含まれています。もう一度読み込んでください。';
  if ((allowMask & denyMask) !== 0) return '同じ権限を許可と拒否の両方には設定できません。競合を解消してください。';
  return null;
}

export function overrideWriteInputFromPreview(
  preview: PermissionOverridePreview,
  allowMask: number,
  denyMask: number,
): PermissionOverrideWriteInput {
  const maskError = validateOverrideMasks(allowMask, denyMask);
  if (maskError) throw new Error(maskError);
  assertPreviewRevisions(preview);
  return {
    allowMask,
    denyMask,
    expectedRevision: preview.currentRevision,
    expectedAuthorizationRevision: preview.authorizationRevision,
  };
}

export function overrideDeleteInputFromPreview(
  preview: PermissionOverridePreview,
): PermissionOverrideDeleteInput {
  assertPreviewRevisions(preview);
  if (preview.currentRevision < 1) throw new Error('削除対象のoverride revisionが不正です');
  return {
    expectedRevision: preview.currentRevision,
    expectedAuthorizationRevision: preview.authorizationRevision,
  };
}

export interface OverridePreviewSummary {
  affectedChannels: number;
  losingUsers: number;
  gainingUsers: number;
  rotationChannels: number;
}

export function summarizeOverridePreview(preview: PermissionOverridePreview): OverridePreviewSummary {
  return {
    affectedChannels: new Set(preview.roomEffects.map((effect) => effect.channelId)).size,
    losingUsers: new Set(preview.roomEffects.flatMap((effect) => effect.lostUserIds)).size,
    gainingUsers: new Set(preview.roomEffects.flatMap((effect) => effect.gainedUserIds)).size,
    rotationChannels: new Set(preview.roomEffects
      .filter((effect) => effect.rotationRequired)
      .map((effect) => effect.channelId)).size,
  };
}

export interface OverrideMutationFailurePlan {
  discardPreview: true;
  refreshPreview: boolean;
}

export function permissionOverridePreviewMatches(
  preview: PermissionOverridePreview,
  expected: {
    target: PermissionOverridePreview['target'];
    workspaceId: string;
    targetId: string;
    roleId: string;
    operation: PermissionOverridePreview['operation'];
  },
): boolean {
  return preview.target === expected.target
    && preview.workspaceId === expected.workspaceId
    && preview.targetId === expected.targetId
    && preview.roleId === expected.roleId
    && preview.operation === expected.operation;
}

export function overrideMutationFailurePlan(error: unknown): OverrideMutationFailurePlan {
  const candidate = typeof error === 'object' && error !== null
    ? error as { status?: unknown; code?: unknown }
    : {};
  return {
    discardPreview: true,
    refreshPreview: candidate.status === 409
      && (candidate.code === 'STALE_PREVIEW' || candidate.code === 'STALE_OVERRIDE'),
  };
}

export function formatChannelPermissionReason(
  reason: ChannelPermissionReason,
  roleNames: ReadonlyMap<string, string>,
): string {
  if (reason.source === 'workspace-owner' && reason.effect === 'allow') return 'ワークスペースの所有者に許可されています';
  if (reason.source === 'role' && reason.effect === 'allow' && reason.roleId) {
    return `ロール「${reason.roleName || roleNames.get(reason.roleId) || '不明'}」が許可`;
  }
  if ((reason.source === 'category' || reason.source === 'channel')
    && (reason.effect === 'allow' || reason.effect === 'deny')
    && reason.roleId) {
    const scope = reason.source === 'category' ? 'カテゴリーの設定' : 'チャンネルの設定';
    const effect = reason.effect === 'allow' ? '許可' : '拒否';
    return `${scope}（${roleNames.get(reason.roleId) || '不明なロール'}）が${effect}`;
  }
  return '詳細を確認できません';
}

function assertPreviewRevisions(preview: PermissionOverridePreview): void {
  if (!Number.isSafeInteger(preview.currentRevision) || preview.currentRevision < 0) {
    throw new Error('Override preview revision is invalid');
  }
  if (!/^[a-f0-9]{64}$/.test(preview.authorizationRevision)) {
    throw new Error('Authorization preview revision is invalid');
  }
}
