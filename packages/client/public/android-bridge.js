/* Loaded only by the bundled Android entry point, before the application. */
(() => {
  'use strict';
  const native = window.alpartsNative;
  if (!native) return;
  let nextId = 0;
  const pending = new Map();
  native.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) request.reject(new Error(message.error));
    else request.resolve(message.result);
  };
  const call = (method, args = {}) => new Promise((resolve, reject) => {
    if (pending.size >= 64) return reject(new Error('操作が混み合っています。'));
    const id = ++nextId;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('操作が完了しませんでした。')); }, method === 'beginSave' ? 300000 : 30000);
    pending.set(id, { resolve, reject, timer });
    native.postMessage(JSON.stringify({ id, method, args }));
  });
  const bridge = Object.freeze({
    getInfo: () => call('info'),
    configureServer: () => Promise.reject(new Error('接続先はアプリの設定から変更してください。')),
    setIdleLockMinutes: (minutes) => call('idle', { minutes }),
    lockNow: () => call('lock'),
    unlockComplete: () => call('unlock'),
    showConnectionSettings: () => Promise.resolve(false),
    secrets: Object.freeze({
      get: (name) => call('get', { name }),
      set: (name, value) => call('set', { name, value }),
      delete: (name) => call('delete', { name }),
    }),
    files: Object.freeze({
      beginSave: (name, expectedBytes, dangerous) => call('beginSave', { name, expectedBytes, dangerous: Boolean(dangerous) }),
      writeSave: async (token, chunk) => {
        const bytes = new Uint8Array(chunk);
        let written = 0;
        for (let offset = 0; offset < bytes.length; offset += 512 * 1024) {
          const part = bytes.subarray(offset, offset + 512 * 1024);
          let encoded = '';
          for (let i = 0; i < part.length; i += 8192) encoded += String.fromCharCode(...part.subarray(i, i + 8192));
          written = await call('writeSave', { token, chunk: btoa(encoded) });
        }
        return written;
      },
      finishSave: (token) => call('finishSave', { token }),
      cancelSave: (token) => call('cancelSave', { token }),
    }),
    onLock: () => () => {},
    onShowConnectionSettings: () => () => {},
  });
  Object.defineProperty(window, 'alpartsDesktop', { value: bridge, writable: false, configurable: false });
})();
