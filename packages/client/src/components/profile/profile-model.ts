import type { MemberProfile } from '@alparts/shared';
import { ApiError } from '../../services/api';
import { AvatarImageError } from '../../services/avatar-image';

export const MAX_BIO_CHARACTERS = 200;
export const MAX_BIO_LINES = 5;

/** Mirrors the server limit: characters are counted as the user sees them. */
export function bioLengthStatus(bio: string) {
  const trimmed = bio.trim();
  const characters = [...trimmed].length;
  const lines = trimmed.length === 0 ? 0 : trimmed.split('\n').length;
  return { characters, lines, ok: characters <= MAX_BIO_CHARACTERS && lines <= MAX_BIO_LINES };
}

export function profileErrorMessage(error: unknown): string {
  if (error instanceof AvatarImageError) {
    if (error.reason === 'type') return 'PNG・JPEG・WebP の画像を選んでください。';
    if (error.reason === 'size') return '5MB以下の画像を選んでください。';
    return '画像を読み込めませんでした。別の画像をお試しください。';
  }
  if (error instanceof ApiError) {
    if (error.code === 'INVALID_AVATAR' || error.code === 'AVATAR_TOO_LARGE') return '画像を読み込めませんでした。別の画像をお試しください。';
    if (error.code === 'PROFILE_APPEAL_USED') return '解除の依頼はすでに使用済みです。';
    if (error.code === 'PROFILE_APPEAL_NEEDS_CHANGE') return 'プロフィールを変更してから依頼してください。';
    if (error.code === 'PROFILE_APPEAL_NOT_PENDING') return '依頼の状態が変わりました。表示を更新してください。';
    if (error.code === 'MEMBER_HIERARCHY') return '自分と同じか上の順位のメンバーには、この操作はできません。';
    if (error.status === 400) return '表示名と自己紹介を確認してください。使用できない文字が含まれているか、長すぎます。';
    if (error.status === 429) return '変更が多すぎます。しばらく待ってからお試しください。';
    return error.message;
  }
  return '保存できませんでした。もう一度お試しください。';
}

export interface ProfileTarget {
  workspaceId: string;
  userId: string;
}

export function profileTargetKey(target: ProfileTarget): string {
  return `${target.workspaceId}:${target.userId}`;
}

/**
 * A loaded profile is shown only for the member it was requested for, so a
 * slow response for a previous member never appears (or is acted on) as the
 * current one.
 */
export function profileForTarget(
  loaded: { key: string; profile: MemberProfile } | null,
  target: ProfileTarget | null,
): MemberProfile | null {
  if (!loaded || !target || loaded.key !== profileTargetKey(target) || loaded.profile.userId !== target.userId) return null;
  return loaded.profile;
}
