import { describe, expect, it, vi } from 'vitest';
import { API_REQUEST_DEADLINE_MS, createApiRequestDeadline } from './api';

describe('API request deadline', () => {
  it('propagates caller cancellation and detaches cleanly', () => {
    const parent = new AbortController();
    const deadline = createApiRequestDeadline(parent.signal, 1_000);
    parent.abort(new Error('caller-cancelled'));
    expect(deadline.signal.aborted).toBe(true);
    expect(deadline.signal.reason).toEqual(new Error('caller-cancelled'));
    deadline.dispose();
  });

  it('aborts at the bounded total-response deadline', () => {
    vi.useFakeTimers();
    try {
      const deadline = createApiRequestDeadline(undefined, 1_000);
      vi.advanceTimersByTime(999);
      expect(deadline.signal.aborted).toBe(false);
      vi.advanceTimersByTime(1);
      expect(deadline.signal.aborted).toBe(true);
      expect(deadline.signal.reason).toEqual(new Error('API_REQUEST_TIMEOUT'));
      deadline.dispose();
      expect(() => createApiRequestDeadline(undefined, API_REQUEST_DEADLINE_MS + 1)).toThrow(
        'Invalid API request deadline',
      );
    } finally {
      vi.useRealTimers();
    }
  });
});
