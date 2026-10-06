import { contextBridge, ipcRenderer } from 'electron';

type DesktopEvent = 'desktop:lock' | 'desktop:show-connection-settings';

function subscribe(channel: DesktopEvent, callback: () => void): () => void {
  if (typeof callback !== 'function') throw new TypeError('A callback is required');
  const listener = () => callback();
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld('alpartsDesktop', Object.freeze({
  getInfo: () => ipcRenderer.invoke('desktop:get-info'),
  configureServer: (serverUrl: string) => ipcRenderer.invoke('desktop:configure-server', serverUrl),
  setIdleLockMinutes: (minutes: number) => ipcRenderer.invoke('desktop:set-idle-lock', minutes),
  lockNow: () => ipcRenderer.invoke('desktop:lock-now'),
  clearHttpCache: () => ipcRenderer.invoke('desktop:clear-http-cache'),
  unlockComplete: () => ipcRenderer.invoke('desktop:unlock-complete'),
  showConnectionSettings: () => ipcRenderer.invoke('desktop:show-connection-settings'),
  setLanguage: (locale: string) => ipcRenderer.invoke('desktop:set-language', locale),
  secrets: Object.freeze({
    get: (name: string) => ipcRenderer.invoke('desktop:secret-get', name),
    set: (name: string, value: string) => ipcRenderer.invoke('desktop:secret-set', name, value),
    delete: (name: string) => ipcRenderer.invoke('desktop:secret-delete', name),
  }),
  files: Object.freeze({
    beginSave: (suggestedName: string, expectedBytes: number, dangerous: boolean) => (
      ipcRenderer.invoke('desktop:file-save-begin', suggestedName, expectedBytes, dangerous)
    ),
    writeSave: (token: string, chunk: ArrayBuffer) => ipcRenderer.invoke('desktop:file-save-write', token, chunk),
    finishSave: (token: string) => ipcRenderer.invoke('desktop:file-save-finish', token),
    cancelSave: (token: string) => ipcRenderer.invoke('desktop:file-save-cancel', token),
  }),
  onLock: (callback: () => void) => subscribe('desktop:lock', callback),
  onShowConnectionSettings: (callback: () => void) => subscribe('desktop:show-connection-settings', callback),
}));
