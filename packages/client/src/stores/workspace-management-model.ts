import { Permissions, type Permission } from '@alparts/shared';
import type { RoleChangePreview, WorkspaceInvitation, WorkspaceRole } from '../services/api';
import { isStaleAuthorizationPreviewError } from '../services/role-authorization-revision';
import { msg, t, type MessageKey } from '../i18n';

const permissionLabels: Record<Permission, MessageKey> = {
  SEND_MESSAGES: msg('メッセージを送信'),
  CREATE_POSTS: msg('フォーラムに投稿を作成'),
  EDIT_MESSAGES: msg('メッセージを編集'),
  DELETE_MESSAGES: msg('メッセージを削除'),
  ADD_REACTIONS: msg('リアクションを追加'),
  MENTION_EVERYONE: msg('@everyone を使用'),
  PIN_MESSAGES: msg('メッセージをピン留め'),
  VIEW_CHANNELS: msg('チャンネルを閲覧'),
  CONNECT_VOICE: msg('通話に参加'),
  MANAGE_CHANNELS: msg('チャンネルを管理'),
  MANAGE_MEMBERS: msg('メンバーと招待を管理'),
  KICK_MEMBERS: msg('メンバーを退出'),
  BAN_MEMBERS: msg('メンバーを利用禁止'),
  MANAGE_WORKSPACE: msg('ワークスペースを管理'),
  MANAGE_ROLES: msg('ロールを管理'),
  VIEW_AUDIT_LOG: msg('監査ログを閲覧'),
  ATTACH_FILES: msg('ファイルを添付'),
  MANAGE_WEBHOOKS: msg('外部サービスからの投稿を管理'),
  MANAGE_BOTS: msg('自動応答アカウントを管理'),
};

export interface PermissionOption {
  name: Permission;
  value: number;
  label: string;
}

export const permissionOptions: PermissionOption[] = (Object.entries(Permissions) as Array<[Permission, number]>)
  .map(([name, value]) => ({ name, value, get label() { return t(permissionLabels[name]); } }));

export function permissionLabel(name: string): string {
  // Unknown values come from the server; never show a raw internal name.
  return Object.prototype.hasOwnProperty.call(permissionLabels, name) ? t(permissionLabels[name as Permission]) : t('その他の権限');
}

export function permissionMaskFromNames(names: Iterable<string>): number {
  const selected = new Set(names);
  return permissionOptions.reduce((mask, option) => selected.has(option.name) ? mask | option.value : mask, 0);
}

export function permissionNamesFromMask(mask: number): Permission[] {
  return permissionOptions
    .filter((option) => (mask & option.value) === option.value)
    .map((option) => option.name);
}

export function invitationStatusAt(
  invitation: Pick<WorkspaceInvitation, 'usedAt' | 'revokedAt' | 'expiresAt'>,
  now: number,
): WorkspaceInvitation['status'] {
  if (invitation.usedAt) return 'used';
  if (invitation.revokedAt) return 'revoked';
  return Date.parse(invitation.expiresAt) <= now ? 'expired' : 'active';
}

export function roleProtection(role: Pick<WorkspaceRole, 'name' | 'standard'>): 'owner' | 'standard' | null {
  if (role.name.toLowerCase() === 'owner') return 'owner';
  return role.standard ? 'standard' : null;
}

export interface PreviewSummary {
  affectedUsers: number;
  gainedPermissions: number;
  lostPermissions: number;
  lostAccessUsers: number;
  gainedAccessUsers: number;
  requiresKeyRotation: boolean;
}

export function summarizeRolePreview(preview: RoleChangePreview): PreviewSummary {
  return {
    affectedUsers: preview.affectedUserIds.length,
    gainedPermissions: preview.affectedMembers.reduce((total, member) => total + member.gained.length, 0),
    lostPermissions: preview.affectedMembers.reduce((total, member) => total + member.lost.length, 0),
    lostAccessUsers: preview.lostAccessUserIds.length,
    gainedAccessUsers: preview.gainedAccessUserIds.length,
    requiresKeyRotation: preview.requiresKeyRotation,
  };
}

export function managementErrorMessage(error: unknown, fallback: string): string {
  const status = typeof error === 'object' && error !== null && 'status' in error
    ? (error as { status?: unknown }).status
    : null;
  if (status === 403 && (error as { code?: unknown }).code === 'MEMBER_HIERARCHY') {
    return t('自分と同じか上の順位のメンバーの権限や表示が減るため、この変更はできません。');
  }
  if (status === 403) {
    return t('権限が不足しています。自身以上の階層のロール操作、または保有していない権限の付与はできません。');
  }
  if (isStaleAuthorizationPreviewError(error)) {
    return t('確認中に権限状態が変更されました。最新の影響を確認し、もう一度保存してください。');
  }
  if (status === 409) {
    return t('変更が競合しました。保護されたロール、使用中のロール、または同名ロールを確認してください。');
  }
  if (status === 404) return t('対象が見つかりません。最新の一覧を再読み込みしてください。');
  if (status === 400) return t('入力内容を確認してください。');
  return fallback;
}

export interface RoleMutationFailurePlan {
  discardPreview: true;
  refreshPreview: boolean;
}

export function roleMutationFailurePlan(error: unknown): RoleMutationFailurePlan {
  return {
    discardPreview: true,
    refreshPreview: isStaleAuthorizationPreviewError(error),
  };
}
