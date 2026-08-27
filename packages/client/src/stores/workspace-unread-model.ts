import type { ChannelReadState } from '@alparts/shared';

export interface WorkspaceUnreadSummary {
  status: 'loading' | 'ready' | 'error';
  total: number;
  badge: string | null;
  mentionStatus: 'none' | 'unknown';
}

export function summarizeWorkspaceUnread(
  states: Record<string, ChannelReadState> | undefined,
  loaded: boolean,
  error: string | null | undefined,
): WorkspaceUnreadSummary {
  if (error) return { status: 'error', total: 0, badge: '?', mentionStatus: 'none' };
  if (!loaded) return { status: 'loading', total: 0, badge: null, mentionStatus: 'none' };
  const total = Object.values(states || {}).reduce((sum, state) => (
    sum + (Number.isSafeInteger(state.unreadCount) && state.unreadCount > 0 ? state.unreadCount : 0)
  ), 0);
  return {
    status: 'ready',
    total,
    badge: total === 0 ? null : total > 99 ? '99+' : String(total),
    mentionStatus: total > 0 ? 'unknown' : 'none',
  };
}

export async function runBounded<T>(
  values: T[],
  concurrency: number,
  worker: (value: T) => Promise<void>,
): Promise<void> {
  const requested = Number.isFinite(concurrency) ? Math.floor(concurrency) : 1;
  const limit = Math.max(1, Math.min(Math.max(1, requested), values.length || 1));
  let nextIndex = 0;
  await Promise.all(Array.from({ length: limit }, async () => {
    while (nextIndex < values.length) {
      const value = values[nextIndex];
      nextIndex += 1;
      await worker(value);
    }
  }));
}
