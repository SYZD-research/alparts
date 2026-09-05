import { ApiConnectionError, ApiError } from '../services/api';

export function authErrorMessage(error: unknown, action: 'login' | 'register'): string {
  if (error instanceof ApiConnectionError) return '接続できませんでした。通信環境を確認して、もう一度お試しください。';
  if (error instanceof ApiError) {
    if ([502, 503, 504].includes(error.status)) return '接続先が応答していません。しばらく待ってから、もう一度お試しください。';
    if (error.code === 'ORIGIN_FORBIDDEN' || error.code === 'ORIGIN_REQUIRED') return 'この接続先ではアプリを利用できません。管理者に確認してください。';
    if (error.code === 'UNAUTHORIZED') return 'メールアドレスまたはパスワードが正しくありません。';
    if (error.code === 'INVITE_REQUIRED') return '招待コードが正しくないか、有効期限が切れています。';
    if (error.code === 'SESSION_LIMIT_REACHED') return 'ログイン中の端末が上限に達しています。別の端末からログアウトしてお試しください。';
    if (error.code === 'DEVICE_LIMIT_REACHED') return '登録済みの端末が上限に達しています。不要な端末の登録を解除してください。';
    if (error.code === 'WORKSPACE_MEMBER_LIMIT') return 'このワークスペースは参加人数の上限に達しています。';
    if (error.code === 'VALIDATION') {
      return action === 'register'
        ? '入力内容を確認してください。パスワードは12文字以上必要です。'
        : 'メールアドレスとパスワードを確認してください。';
    }
  }
  if (error instanceof Error && error.message === 'API_REQUEST_TIMEOUT') {
    return '接続に時間がかかっています。通信環境を確認して、もう一度お試しください。';
  }
  return action === 'register'
    ? 'アカウントを作成できませんでした。もう一度お試しください。'
    : 'ログインできませんでした。もう一度お試しください。';
}
