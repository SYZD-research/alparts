// Whether this browser still owes the server a sign-out. The session cookie is
// HttpOnly, so until the server confirms the sign-out the cookie may still
// identify a live session; the flag keeps that from being forgotten on restart.
const STORAGE_KEY = 'alparts.signOutPending';

// Holds the flag for this page when storage is unavailable.
let remembered = false;

export function isSignOutPending(): boolean {
  if (remembered) return true;
  try {
    return globalThis.localStorage?.getItem(STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export function setSignOutPending(pending: boolean): void {
  remembered = pending;
  try {
    if (pending) globalThis.localStorage?.setItem(STORAGE_KEY, '1');
    else globalThis.localStorage?.removeItem(STORAGE_KEY);
  } catch {
    // Without storage the flag lasts until the page is closed.
  }
}
