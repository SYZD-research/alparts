export {};

export interface AlpartsDesktopInfo {
  platform: 'windows' | 'macos' | 'linux' | 'android';
  version: string;
  serverUrl: string | null;
  idleLockMinutes: number;
  locked: boolean;
  secureStorageReady: boolean;
  serverManaged: boolean;
}

export interface AlpartsDesktopBridge {
  getInfo(): Promise<AlpartsDesktopInfo>;
  configureServer(serverUrl: string): Promise<AlpartsDesktopInfo>;
  setIdleLockMinutes(minutes: number): Promise<number>;
  lockNow(): Promise<boolean>;
  clearHttpCache(): Promise<boolean>;
  unlockComplete(): Promise<boolean>;
  showConnectionSettings(): Promise<boolean>;
  /** Native menus and dialogs follow the language chosen in the app. */
  setLanguage?(locale: 'ja' | 'en'): Promise<boolean>;
  secrets: {
    get(name: string): Promise<string | null>;
    set(name: string, value: string): Promise<boolean>;
    delete(name: string): Promise<boolean>;
  };
  files: {
    beginSave(suggestedName: string, expectedBytes: number, dangerous: boolean): Promise<string | null>;
    writeSave(token: string, chunk: ArrayBuffer): Promise<number>;
    finishSave(token: string): Promise<boolean>;
    cancelSave(token: string): Promise<boolean>;
  };
  onLock(callback: () => void): () => void;
  onShowConnectionSettings(callback: () => void): () => void;
}

declare global {
  interface Window {
    alpartsDesktop?: AlpartsDesktopBridge;
  }
}
