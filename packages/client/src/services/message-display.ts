const UNAVAILABLE_MESSAGE_TEXT: Record<string, string> = {
  '[表示できないメッセージ]': 'このメッセージを表示できません',
  '[メッセージを検証できませんでした]': '安全性を確認できないため、このメッセージを表示できません',
  '[改ざんを検出しました]': '安全性を確認できないため、このメッセージを表示できません',
};

export function userFacingMessageText(content: string): string {
  return UNAVAILABLE_MESSAGE_TEXT[content] || content;
}
