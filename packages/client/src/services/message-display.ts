import { t, type MessageKey, msg } from '../i18n';
// Internal markers placed in a message's content when it cannot be shown.
// They are compared, never displayed, so they are not translated.
export const UNAVAILABLE_MESSAGE_MARKER = '[表示できないメッセージ]';
export const UNVERIFIED_MESSAGE_MARKER = '[メッセージを検証できませんでした]';
export const TAMPERED_MESSAGE_MARKER = '[改ざんを検出しました]';

const UNAVAILABLE_MESSAGE_TEXT: Record<string, MessageKey> = {
  [UNAVAILABLE_MESSAGE_MARKER]: msg('このメッセージを表示できません'),
  [UNVERIFIED_MESSAGE_MARKER]: msg('安全性を確認できないため、このメッセージを表示できません'),
  [TAMPERED_MESSAGE_MARKER]: msg('安全性を確認できないため、このメッセージを表示できません'),
};

export function userFacingMessageText(content: string): string {
  const key = UNAVAILABLE_MESSAGE_TEXT[content];
  return key ? t(key) : content;
}
