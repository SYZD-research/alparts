/** Languages the registration emails are written in. */
export type EmailLocale = 'ja' | 'en';

interface EmailText {
  subject: string;
  text: string;
}

/**
 * The first supported language in an Accept-Language header, by quality and
 * then order. The client sends the language the user chose in the app.
 */
export function emailLocale(acceptLanguage: string | undefined): EmailLocale {
  const ranges = (acceptLanguage ?? '')
    .split(',')
    .slice(0, 20)
    .map((part, index) => {
      const [tag = '', ...parameters] = part.trim().split(';');
      const quality = parameters.map((parameter) => /^\s*q=([01](?:\.\d{0,3})?)\s*$/i.exec(parameter)?.[1]).find(Boolean);
      return { language: tag.trim().toLowerCase().split('-')[0], quality: quality === undefined ? 1 : Number(quality), index };
    })
    .filter((range) => range.quality > 0)
    .sort((left, right) => right.quality - left.quality || left.index - right.index);
  for (const { language } of ranges) {
    if (language === 'ja' || language === 'en') return language;
  }
  return 'en';
}

export function existingAccountEmail(locale: EmailLocale): EmailText {
  return locale === 'ja'
    ? {
      subject: 'alparts のアカウントについて',
      text: 'このメールアドレスで alparts のアカウントを作成しようとする操作がありました。\n'
        + 'このアドレスのアカウントはすでにあります。ご自身の操作であれば、ログインしてください。\n'
        + '心当たりがない場合は、このメールを無視してください。\n',
    }
    : {
      subject: 'About your alparts account',
      text: 'Someone tried to create an alparts account with this email address.\n'
        + 'An account already exists for this address. If this was you, sign in instead.\n'
        + 'If it was not you, you can ignore this email.\n',
    };
}

export function registrationCodeEmail(locale: EmailLocale, code: string): EmailText {
  return locale === 'ja'
    ? {
      subject: 'alparts の確認コード',
      text: `alparts のアカウント作成に使う確認コードです。\n\n${code}\n\n`
        + 'このコードは15分間有効です。心当たりがない場合は、このメールを無視してください。\n',
    }
    : {
      subject: 'Your alparts verification code',
      text: `Use this code to create your alparts account.\n\n${code}\n\n`
        + 'The code is valid for 15 minutes. If you did not ask for it, you can ignore this email.\n',
    };
}
