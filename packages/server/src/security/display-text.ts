import { z } from 'zod';

// Names are single-line labels. Reject formatting controls before trim() so
// invisible prefixes cannot disguise a different identity in member lists.
// Blank-rendering letters/symbols (Hangul fillers, Braille blank) are not
// formatting controls, so they are listed explicitly.
const UNSAFE_DISPLAY_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u034f\u115f\u1160\u17b4\u17b5\u2800\u3164\uffa0]/u;
// A non-empty name must show at least one letter, digit, punctuation or symbol;
// spaces and combining marks alone would render as an invisible identity.
const VISIBLE_DISPLAY_TEXT = /[\p{L}\p{N}\p{P}\p{S}]/u;
export function displayText(maxLength = 100, allowEmpty = false) {
  return z.string().refine((text) => !UNSAFE_DISPLAY_TEXT.test(text), '名前に使用できない文字が含まれています。')
    .transform((text) => text.normalize('NFC').trim())
    .pipe(z.string().min(allowEmpty ? 0 : 1).max(maxLength))
    .refine((text) => text.length === 0 || VISIBLE_DISPLAY_TEXT.test(text), '名前に表示できる文字を含めてください。');
}
