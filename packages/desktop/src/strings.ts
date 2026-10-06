/** Languages of the native menu and dialogs; they follow the app's choice. */
export type DesktopLocale = 'ja' | 'en';

export interface DesktopStrings {
  saveAttachmentTitle: string;
  saveButton: string;
  startFailedTitle: string;
  startFailedMessage: string;
  appMenu: string;
  lock: string;
  changeServer: string;
  editMenu: string;
  viewMenu: string;
  windowMenu: string;
}

const STRINGS: Record<DesktopLocale, DesktopStrings> = {
  ja: {
    saveAttachmentTitle: '添付ファイルを保存',
    saveButton: '保存',
    startFailedTitle: 'alpartsを開始できません',
    startFailedMessage: 'アプリを開始できませんでした。アプリを終了し、もう一度起動してください。',
    appMenu: 'アプリ',
    lock: 'ロック',
    changeServer: '接続先を変更',
    editMenu: '編集',
    viewMenu: '表示',
    windowMenu: 'ウィンドウ',
  },
  en: {
    saveAttachmentTitle: 'Save attachment',
    saveButton: 'Save',
    startFailedTitle: 'alparts cannot start',
    startFailedMessage: 'The app could not start. Quit the app and open it again.',
    appMenu: 'App',
    lock: 'Lock',
    changeServer: 'Change server',
    editMenu: 'Edit',
    viewMenu: 'View',
    windowMenu: 'Window',
  },
};

/** The first supported system language, else English, matching the web client. */
export function desktopLocale(languages: readonly string[]): DesktopLocale {
  for (const language of languages) {
    const base = language.trim().toLowerCase().split(/[-_]/)[0];
    if (base === 'ja' || base === 'en') return base;
  }
  return 'en';
}

export function normalizeDesktopLocale(value: unknown): DesktopLocale {
  if (value === 'ja' || value === 'en') return value;
  throw new Error('INVALID_LOCALE');
}

export function desktopStrings(locale: DesktopLocale): DesktopStrings {
  return STRINGS[locale];
}
