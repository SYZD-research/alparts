import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AlpartsDesktopBridge } from '../types/desktop';

// The Android entry point loads public/android-bridge.js where the desktop app
// has its preload script, and the app calls the same bridge on both.
const BRIDGE_SCRIPT = Object.values(import.meta.glob<string>(
  '../../public/android-bridge.js',
  { query: '?raw', import: 'default', eager: true },
))[0];
type Method = Exclude<keyof AlpartsDesktopBridge, 'secrets' | 'files' | 'setLanguage'>;
const METHODS: Record<Method, true> = {
  getInfo: true,
  configureServer: true,
  setIdleLockMinutes: true,
  lockNow: true,
  clearHttpCache: true,
  unlockComplete: true,
  showConnectionSettings: true,
  onLock: true,
  onShowConnectionSettings: true,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Android bridge', () => {
  it('provides every method of the desktop bridge the app calls', async () => {
    const posted: string[] = [];
    const page: { alpartsNative: unknown; alpartsDesktop?: AlpartsDesktopBridge } = {
      alpartsNative: { postMessage: (message: string) => posted.push(message), onmessage: null },
    };
    vi.stubGlobal('window', page);
    new Function(BRIDGE_SCRIPT)();
    const bridge = page.alpartsDesktop!;
    for (const name of Object.keys(METHODS) as Method[]) expect(typeof bridge[name], name).toBe('function');
    for (const name of ['get', 'set', 'delete'] as const) expect(typeof bridge.secrets[name], name).toBe('function');
    for (const name of ['beginSave', 'writeSave', 'finishSave', 'cancelSave'] as const) {
      expect(typeof bridge.files[name], name).toBe('function');
    }
    // Sign-out waits for this on every platform; Android has nothing to clear.
    await expect(bridge.clearHttpCache()).resolves.toBe(false);
    expect(posted).toEqual([]);
  });
});
