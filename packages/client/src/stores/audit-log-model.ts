import type { AuditLogEntry } from '../services/api';

export interface SafeAuditDetail {
  key: string;
  value: string;
}

const DETAIL_LABELS: Record<string, string> = {
  recipientCount: '対象人数',
  resultCount: '件数',
  changed: '変更',
  requiresKeyRotation: '追加の更新',
  expiresAt: '有効期限',
  name: '名前',
  position: '並び順',
};

const ACTION_LABELS: Record<string, string> = {
  'user.register': 'アカウントを作成',
  'user.login': 'ログイン',
  'user.profile.update': 'プロフィールを変更',
  'user.avatar.update': 'プロフィール画像を変更',
  'user.avatar.remove': 'プロフィール画像を削除',
  'profile.flag': 'プロフィールに警告を付与',
  'profile.unflag': 'プロフィールの警告を解除',
  'profile.appeal.request': 'プロフィールの警告の解除を依頼',
  'profile.appeal.deny': 'プロフィールの警告の解除依頼を却下',
  'user.login.failed': 'ログインに失敗',
  'user.logout': 'ログアウト',
  'session.revoke': 'ログインを終了',
  'session.revoke_all': 'すべてのログインを終了',
  'device.register': '端末を登録',
  'device.bind': '端末を登録',
  'device.revoke': '端末の登録を解除',
  'workspace.create': 'ワークスペースを作成',
  'workspace.member.remove': 'メンバーを削除',
  'workspace.invitation.create': '招待を作成',
  'workspace.invitation.use': '招待を使用',
  'workspace.invitation.revoke': '招待を無効化',
  'role.create': 'ロールを作成',
  'role.update': 'ロールを変更',
  'role.delete': 'ロールを削除',
  'role.assign': 'ロールを割り当て',
  'role.unassign': 'ロールの割り当てを解除',
  'category.create': 'カテゴリーを作成',
  'category.update': 'カテゴリーを変更',
  'category.delete': 'カテゴリーを削除',
  'channel.create': 'チャンネルを作成',
  'channel.update': 'チャンネルを変更',
  'channel.delete': 'チャンネルを削除',
  'channel.member.add': 'チャンネルにメンバーを追加',
  'channel.member.remove': 'チャンネルからメンバーを削除',
  'channel.preference.update': 'チャンネルの個人設定を変更',
  'channel.permission-override.upsert': 'チャンネル権限を変更',
  'channel.permission-override.delete': 'チャンネル権限を削除',
  'category.permission-override.upsert': 'カテゴリー権限を変更',
  'category.permission-override.delete': 'カテゴリー権限を削除',
  'channel.key.epoch.propose': 'チャンネルの利用準備を更新',
  'channel.key.epoch.recovery.propose': 'チャンネルの利用準備を復旧',
  'channel.key.epoch.fresh_start': '過去のメッセージを使わずチャンネルを再開',
  'channel.key.delivery.add': 'チャンネルの利用準備を更新',
  'channel.key.acknowledge': 'チャンネルの利用準備を確認',
  'channel.key.epoch.abort': 'チャンネルの利用準備を中止',
  'dm.create': 'ダイレクトメッセージを作成',
  'dm.reuse': 'ダイレクトメッセージを開く',
  'message.create': 'メッセージを送信',
  'message.edit': 'メッセージを編集',
  'message.delete': 'メッセージを削除',
  'message.reaction.add': 'リアクションを追加',
  'message.reaction.remove': 'リアクションを削除',
  'message.pin.add': 'メッセージをピン留め',
  'message.pin.remove': 'メッセージのピン留めを解除',
  'message.bookmark.add': 'メッセージを保存',
  'message.bookmark.remove': 'メッセージを保存済みから削除',
  'attachment.upload.create': 'ファイル送信を開始',
  'attachment.upload.cancel': 'ファイル送信を中止',
  'attachment.create': 'ファイルを送信',
  'audit.view': '操作履歴を表示',
  'audit.integrity.view': '操作履歴の状態を確認',
  'audit.checkpoint.provision': '操作履歴を保守',
};

const TARGET_LABELS: Record<string, string> = {
  user: 'アカウント',
  session: 'ログイン',
  device: '端末',
  workspace: 'ワークスペース',
  workspace_invitation: '招待',
  role: 'ロール',
  category: 'カテゴリー',
  channel: 'チャンネル',
  message: 'メッセージ',
  attachment: 'ファイル',
};

export function safeAuditDetails(details: unknown): SafeAuditDetail[] {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return [];
  const entries: SafeAuditDetail[] = [];
  for (const [key, value] of Object.entries(details as Record<string, unknown>)) {
    const label = DETAIL_LABELS[key];
    if (!label) continue;
    const formatted = formatSafeScalar(value, key);
    if (formatted !== null) entries.push({ key: label, value: formatted });
  }
  return entries;
}

export function auditActionLabel(action: string): string {
  const normalized = action.endsWith('.replay') ? action.slice(0, -'.replay'.length) : action;
  if (ACTION_LABELS[normalized]) return ACTION_LABELS[normalized];
  if (normalized.startsWith('message.')) return 'メッセージを更新';
  if (normalized.startsWith('channel.')) return 'チャンネルを更新';
  if (normalized.startsWith('category.')) return 'カテゴリーを更新';
  if (normalized.startsWith('role.')) return 'ロールを更新';
  if (normalized.startsWith('workspace.')) return 'ワークスペースを更新';
  if (normalized.startsWith('attachment.')) return 'ファイルを更新';
  return '管理操作';
}

export function auditTargetLabel(targetType: string | null): string | null {
  return targetType ? TARGET_LABELS[targetType] || null : null;
}

export function auditResult(entry: Pick<AuditLogEntry, 'details'>): 'success' | 'failure' | 'unknown' {
  if (!entry.details || typeof entry.details !== 'object' || Array.isArray(entry.details)) return 'unknown';
  const result = (entry.details as Record<string, unknown>).result;
  return result === 'success' || result === 'failure' ? result : 'unknown';
}

function formatSafeScalar(value: unknown, key: string): string | null {
  if (typeof value === 'boolean') return value ? 'あり' : 'なし';
  if (typeof value === 'number') return String(value);
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (!normalized) return null;
  if (key === 'expiresAt') {
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date.toLocaleString('ja-JP');
  }
  return normalized.slice(0, 160);
}
