import { afterEach, describe, expect, it, vi } from 'vitest';
import { isSignOutPending, setSignOutPending } from './pending-sign-out';

afterEach(() => {
  setSignOutPending(false);
  vi.unstubAllGlobals();
});

function memoryStorage() {
  const stored = new Map<string, string>();
  return {
    stored,
    storage: {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => void stored.set(key, value),
      removeItem: (key: string) => void stored.delete(key),
    },
  };
}

describe('pending sign-out flag', () => {
  it('is kept in the browser storage until it is cleared', () => {
    const { stored, storage } = memoryStorage();
    vi.stubGlobal('localStorage', storage);
    expect(isSignOutPending()).toBe(false);
    setSignOutPending(true);
    expect(stored.get('alparts.signOutPending')).toBe('1');
    expect(isSignOutPending()).toBe(true);
    setSignOutPending(false);
    expect(stored.size).toBe(0);
    expect(isSignOutPending()).toBe(false);
  });

  it('is found again by a page that starts later', () => {
    const { stored, storage } = memoryStorage();
    vi.stubGlobal('localStorage', storage);
    stored.set('alparts.signOutPending', '1');
    expect(isSignOutPending()).toBe(true);
  });

  it('ignores any other stored value', () => {
    const { stored, storage } = memoryStorage();
    vi.stubGlobal('localStorage', storage);
    stored.set('alparts.signOutPending', 'yes');
    expect(isSignOutPending()).toBe(false);
  });

  it('holds for the page when storage is missing or refuses to work', () => {
    setSignOutPending(true);
    expect(isSignOutPending()).toBe(true);
    setSignOutPending(false);

    const refuse = () => { throw new DOMException('denied', 'SecurityError'); };
    vi.stubGlobal('localStorage', { getItem: refuse, setItem: refuse, removeItem: refuse });
    expect(isSignOutPending()).toBe(false);
    setSignOutPending(true);
    expect(isSignOutPending()).toBe(true);
    setSignOutPending(false);
    expect(isSignOutPending()).toBe(false);
  });
});
