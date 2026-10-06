import { useCallback } from 'react';
import { en, type MessageKey, type MessageParams } from './en';
import { formattingLocale, useLocaleStore, type Locale } from './locale';

export { LANGUAGE_NAMES, SUPPORTED_LOCALES, useLocaleStore, type Locale, type LocalePreference } from './locale';
export type { MessageKey, MessageParams } from './en';

function interpolate(template: string, params?: MessageParams): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in params ? String(params[name]) : match));
}

// A key may end in `|context` when the same Japanese text needs different
// English, e.g. 'すべて|notification-level'. The context is never shown.
const CONTEXT_SUFFIX = /\|[a-z-]+$/;

/**
 * Japanese text is the message key. English comes from the catalog, so a key
 * missing there is a type error rather than untranslated UI.
 */
export function translate(locale: Locale, key: MessageKey, params?: MessageParams): string {
  if (locale === 'ja') return interpolate(key.replace(CONTEXT_SUFFIX, ''), params);
  const message = en[key];
  return typeof message === 'function' ? message(params ?? {}) : interpolate(message, params);
}

/** Translates in the current language; for code outside React rendering. */
export function t(key: MessageKey, params?: MessageParams): string {
  return translate(useLocaleStore.getState().locale, key, params);
}

/** Marks text for translation where it is defined; translate it with t() where it is shown. */
export function msg<K extends MessageKey>(key: K): K {
  return key;
}

export function currentLocale(): Locale {
  return useLocaleStore.getState().locale;
}

/** The language tag for Intl date and number formatting. */
export function intlLocale(): string {
  return formattingLocale(currentLocale());
}

export function useLocale(): Locale {
  return useLocaleStore((state) => state.locale);
}

/** A translator that re-renders the component when the language changes. */
export function useT(): (key: MessageKey, params?: MessageParams) => string {
  const locale = useLocale();
  return useCallback((key: MessageKey, params?: MessageParams) => translate(locale, key, params), [locale]);
}
