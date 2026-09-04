import type { AlpartsDesktopBridge, AlpartsDesktopInfo } from '../types/desktop';

export const DESKTOP_IDLE_LOCK_MINUTES = [1, 5, 15, 30, 60] as const;

export function getDesktopBridge(): AlpartsDesktopBridge | null {
  if (typeof window === 'undefined') return null;
  return window.alpartsDesktop || null;
}

export async function getDesktopInfo(): Promise<AlpartsDesktopInfo | null> {
  return getDesktopBridge()?.getInfo() ?? null;
}

export async function getDesktopSecret(name: string): Promise<string | null> {
  const bridge = getDesktopBridge();
  return bridge ? bridge.secrets.get(name) : null;
}

export async function setDesktopSecret(name: string, value: string): Promise<boolean> {
  const bridge = getDesktopBridge();
  if (!bridge) return false;
  await bridge.secrets.set(name, value);
  return true;
}

export async function deleteDesktopSecret(name: string): Promise<void> {
  await getDesktopBridge()?.secrets.delete(name);
}
