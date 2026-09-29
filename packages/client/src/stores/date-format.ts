/** Local date/time text; a malformed server value never renders as "Invalid Date". */
export function formatDateTime(value: string | number | Date): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '日時不明' : date.toLocaleString('ja-JP');
}

export function formatDateParts(value: string | number | Date, options: Intl.DateTimeFormatOptions, kind: 'date' | 'time'): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return kind === 'date' ? '日付不明' : '時刻不明';
  return kind === 'date' ? date.toLocaleDateString('ja-JP', options) : date.toLocaleTimeString('ja-JP', options);
}
