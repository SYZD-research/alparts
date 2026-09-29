import { describe, expect, it } from 'vitest';
import { formatDateParts, formatDateTime } from './date-format';

describe('date formatting', () => {
  it('never renders an invalid date literally', () => {
    expect(formatDateTime('not-a-date')).toBe('日時不明');
    expect(formatDateParts('', { hour: '2-digit' }, 'time')).toBe('時刻不明');
    expect(formatDateParts('x', { year: 'numeric' }, 'date')).toBe('日付不明');
    expect(formatDateTime('2026-09-29T00:00:00Z')).not.toContain('Invalid');
  });
});
