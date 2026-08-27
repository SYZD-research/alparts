export const LARGE_PASTE_BYTE_THRESHOLD = 2000;
export const LARGE_PASTE_LINE_THRESHOLD = 20;

export interface LargePastePreview {
  byteCount: number;
  lineCount: number;
  head: string;
  tail: string;
  omitted: boolean;
}

export function previewLargePaste(text: string): LargePastePreview | null {
  const byteCount = new TextEncoder().encode(text).byteLength;
  const lineCount = countLines(text);
  if (byteCount < LARGE_PASTE_BYTE_THRESHOLD && lineCount < LARGE_PASTE_LINE_THRESHOLD) return null;
  const snippetLength = 500;
  const omitted = text.length > snippetLength * 2;
  return {
    byteCount,
    lineCount,
    head: previewSafeText(omitted ? text.slice(0, snippetLength) : text),
    tail: omitted ? previewSafeText(text.slice(-snippetLength)) : '',
    omitted,
  };
}

export function insertPastedText(current: string, pasted: string, start: number, end: number): string {
  const safeStart = Math.max(0, Math.min(Math.floor(start), current.length));
  const safeEnd = Math.max(safeStart, Math.min(Math.floor(end), current.length));
  return `${current.slice(0, safeStart)}${pasted}${current.slice(safeEnd)}`;
}

function previewSafeText(value: string): string {
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '�');
}

function countLines(value: string): number {
  if (value.length === 0) return 0;
  let lines = 1;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === '\n') lines += 1;
    else if (value[index] === '\r') {
      lines += 1;
      if (value[index + 1] === '\n') index += 1;
    }
  }
  return lines;
}
