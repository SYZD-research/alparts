import type { AuditLogEntry } from '../services/api';
import { intlLocale, msg, t, type MessageKey } from '../i18n';

export interface SafeAuditDetail {
  key: string;
  value: string;
}

const DETAIL_LABELS: Record<string, MessageKey> = {
  recipientCount: msg('対象人数'),
  resultCount: msg('件数'),
  changed: msg('変更'),
  requiresKeyRotation: msg('追加の更新'),
  expiresAt: msg('有効期限'),
  name: msg('名前'),
  position: msg('並び順|position'),
};

const ACTION_LABELS: Record<string, MessageKey> = {
  'user.register': msg('アカウントを作成'),
  'user.login': msg('ログイン|audit'),
  'user.profile.update': msg('プロフィールを変更'),
  'user.avatar.update': msg('プロフィール画像を変更'),
  'user.avatar.remove': msg('プロフィール画像を削除'),
  'profile.flag': msg('プロフィールに警告を付与'),
  'profile.unflag': msg('プロフィールの警告を解除'),
  'profile.appeal.request': msg('プロフィールの警告の解除を依頼'),
  'profile.appeal.deny': msg('プロフィールの警告の解除依頼を却下'),
  'user.login.failed': msg('ログインに失敗'),
  'user.logout': msg('ログアウト|audit'),
  'session.revoke': msg('ログインを終了'),
  'session.revoke_all': msg('すべてのログインを終了'),
  'user.password.change': msg('パスワードを変更'),
  'user.password_login.enable': msg('パスワードでのログインをオン'),
  'user.password_login.disable': msg('パスワードでのログインをオフ'),
  'account.password.reset': msg('パスワードを再設定'),
  'device.register': msg('端末を登録'),
  'device.bind': msg('端末を登録'),
  'device.revoke': msg('端末の登録を解除'),
  'workspace.create': msg('ワークスペースを作成'),
  'workspace.member.remove': msg('メンバーを削除'),
  'workspace.invitation.create': msg('招待を作成'),
  'workspace.invitation.use': msg('招待を使用'),
  'workspace.invitation.revoke': msg('招待を無効化'),
  'role.create': msg('ロールを作成'),
  'role.update': msg('ロールを変更'),
  'role.delete': msg('ロールを削除'),
  'role.assign': msg('ロールを割り当て'),
  'role.unassign': msg('ロールの割り当てを解除'),
  'category.create': msg('カテゴリーを作成'),
  'category.update': msg('カテゴリーを変更'),
  'category.delete': msg('カテゴリーを削除'),
  'channel.create': msg('チャンネルを作成'),
  'channel.update': msg('チャンネルを変更'),
  'channel.delete': msg('チャンネルを削除'),
  'channel.member.add': msg('チャンネルにメンバーを追加'),
  'channel.member.remove': msg('チャンネルからメンバーを削除'),
  'channel.preference.update': msg('チャンネルの個人設定を変更'),
  'channel.permission-override.upsert': msg('チャンネル権限を変更'),
  'channel.permission-override.delete': msg('チャンネル権限を削除'),
  'category.permission-override.upsert': msg('カテゴリー権限を変更'),
  'category.permission-override.delete': msg('カテゴリー権限を削除'),
  'channel.key.epoch.propose': msg('チャンネルの利用準備を更新'),
  'channel.key.epoch.recovery.propose': msg('チャンネルの利用準備を復旧'),
  'channel.key.epoch.fresh_start': msg('過去のメッセージを使わずチャンネルを再開'),
  'channel.key.delivery.add': msg('チャンネルの利用準備を更新'),
  'channel.key.acknowledge': msg('チャンネルの利用準備を確認'),
  'channel.key.epoch.abort': msg('チャンネルの利用準備を中止'),
  'channel.key.group.create': msg('チャンネルの利用準備を開始'),
  'channel.key.group.commit': msg('チャンネルの利用準備を更新'),
  // A resent group change (`channel.key.group.replay`) names no kind.
  'channel.key.group': msg('チャンネルの利用準備を更新'),
  'channel.key.group.fresh_start': msg('過去のメッセージを使わずチャンネルを再開'),
  'channel.mls.member_package': msg('チャンネルへの参加を準備'),
  'dm.create': msg('ダイレクトメッセージを作成'),
  'dm.reuse': msg('ダイレクトメッセージを開く'),
  'message.create': msg('メッセージを送信'),
  'message.edit': msg('メッセージを編集'),
  'message.delete': msg('メッセージを削除'),
  'message.reaction.add': msg('リアクションを追加'),
  'message.reaction.remove': msg('リアクションを削除'),
  'message.pin.add': msg('メッセージをピン留め'),
  'message.pin.remove': msg('メッセージのピン留めを解除'),
  'message.bookmark.add': msg('メッセージを保存'),
  'message.bookmark.remove': msg('メッセージを保存済みから削除'),
  'attachment.upload.create': msg('ファイル送信を開始'),
  'attachment.upload.cancel': msg('ファイル送信を中止'),
  'attachment.create': msg('ファイルを送信'),
  'audit.view': msg('操作履歴を表示'),
  'audit.integrity.view': msg('操作履歴の状態を確認'),
  'audit.checkpoint.provision': msg('操作履歴を保守'),
};

const TARGET_LABELS: Record<string, MessageKey> = {
  user: msg('アカウント'),
  session: msg('ログイン|session'),
  device: msg('端末'),
  workspace: msg('ワークスペース'),
  workspace_invitation: msg('招待'),
  role: msg('ロール|single'),
  category: msg('カテゴリー'),
  channel: msg('チャンネル|single'),
  message: msg('メッセージ'),
  attachment: msg('ファイル'),
};

export function safeAuditDetails(details: unknown): SafeAuditDetail[] {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return [];
  const entries: SafeAuditDetail[] = [];
  for (const [key, value] of Object.entries(details as Record<string, unknown>)) {
    const label = DETAIL_LABELS[key];
    if (!label) continue;
    const formatted = formatSafeScalar(value, key);
    if (formatted !== null) entries.push({ key: t(label), value: formatted });
  }
  return entries;
}

export function auditActionLabel(action: string): string {
  const normalized = action.endsWith('.replay') ? action.slice(0, -'.replay'.length) : action;
  if (ACTION_LABELS[normalized]) return t(ACTION_LABELS[normalized]);
  if (normalized.startsWith('message.')) return t('メッセージを更新');
  if (normalized.startsWith('channel.')) return t('チャンネルを更新');
  if (normalized.startsWith('category.')) return t('カテゴリーを更新');
  if (normalized.startsWith('role.')) return t('ロールを更新');
  if (normalized.startsWith('workspace.')) return t('ワークスペースを更新');
  if (normalized.startsWith('attachment.')) return t('ファイルを更新');
  return t('管理操作');
}

export function auditTargetLabel(targetType: string | null): string | null {
  const label = targetType ? TARGET_LABELS[targetType] : undefined;
  return label ? t(label) : null;
}

export function auditResult(entry: Pick<AuditLogEntry, 'details'>): 'success' | 'failure' | 'unknown' {
  if (!entry.details || typeof entry.details !== 'object' || Array.isArray(entry.details)) return 'unknown';
  const result = (entry.details as Record<string, unknown>).result;
  return result === 'success' || result === 'failure' ? result : 'unknown';
}

function formatSafeScalar(value: unknown, key: string): string | null {
  if (typeof value === 'boolean') return value ? t('あり') : t('なし');
  if (typeof value === 'number') return String(value);
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (!normalized) return null;
  if (key === 'expiresAt') {
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date.toLocaleString(intlLocale());
  }
  return normalized.slice(0, 160);
}
