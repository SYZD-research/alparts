import { z } from 'zod';

// Names are single-line labels. Reject formatting controls before trim() so
// invisible prefixes cannot disguise a different identity in member lists.
const UNSAFE_DISPLAY_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u034f\u17b4\u17b5\u3164\uffa0]/u;
export function displayText(maxLength = 100, allowEmpty = false) {
  return z.string().refine((text) => !UNSAFE_DISPLAY_TEXT.test(text), '名前に使用できない文字が含まれています。')
    .transform((text) => text.normalize('NFC').trim())
    .pipe(z.string().min(allowEmpty ? 0 : 1).max(maxLength));
}
