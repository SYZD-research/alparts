import { create } from 'zustand';

export const SUPPORTED_LOCALES = ['ja', 'en'] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];
/** Each language is named in itself so it can be found whichever one is shown. */
export const LANGUAGE_NAMES: Record<Locale, string> = { ja: '日本語', en: 'English' };

/** `system` follows the browser or operating system language. */
export type LocalePreference = Locale | 'system';

const STORAGE_KEY = 'alparts.language';
const FALLBACK_LOCALE: Locale = 'en';

/** The first supported language in the user's preference order, else English. */
export function detectLocale(languages: readonly string[]): Locale {
  for (const language of languages) {
    const base = language.trim().toLowerCase().split(/[-_]/)[0];
    const match = SUPPORTED_LOCALES.find((locale) => locale === base);
    if (match) return match;
  }
  return FALLBACK_LOCALE;
}

function environmentLanguages(): string[] {
  if (typeof navigator === 'undefined') return [];
  if (Array.isArray(navigator.languages) && navigator.languages.length > 0) return [...navigator.languages];
  return navigator.language ? [navigator.language] : [];
}

export function resolveLocale(preference: LocalePreference, languages = environmentLanguages()): Locale {
  return preference === 'system' ? detectLocale(languages) : preference;
}

/**
 * The language tag used for dates and numbers: the environment's own regional
 * variant when it is the same language (en-GB stays en-GB), else a default.
 */
export function formattingLocale(locale: Locale, languages = environmentLanguages()): string {
  const regional = languages.find((language) => language.toLowerCase().split(/[-_]/)[0] === locale);
  if (regional) return regional;
  return locale === 'ja' ? 'ja-JP' : 'en-US';
}

function readPreference(): LocalePreference {
  try {
    const stored = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (stored === 'system' || SUPPORTED_LOCALES.includes(stored as Locale)) return stored as LocalePreference;
  } catch {
    // Storage can be unavailable; the environment language still applies.
  }
  return 'system';
}

function writePreference(preference: LocalePreference): void {
  try {
    if (preference === 'system') globalThis.localStorage?.removeItem(STORAGE_KEY);
    else globalThis.localStorage?.setItem(STORAGE_KEY, preference);
  } catch {
    // The choice still applies for this session.
  }
}

interface LocaleState {
  preference: LocalePreference;
  locale: Locale;
  setPreference: (preference: LocalePreference) => void;
  /** Re-reads the environment language, e.g. after the system language changed. */
  refresh: () => void;
}

export const useLocaleStore = create<LocaleState>((set, get) => {
  const preference = readPreference();
  return {
    preference,
    locale: resolveLocale(preference),
    setPreference: (next) => {
      writePreference(next);
      set({ preference: next, locale: resolveLocale(next) });
    },
    refresh: () => {
      const locale = resolveLocale(get().preference);
      if (locale !== get().locale) set({ locale });
    },
  };
});

function applyDocumentLanguage(locale: Locale): void {
  if (typeof document !== 'undefined') document.documentElement.lang = locale;
}

if (typeof window !== 'undefined') {
  applyDocumentLanguage(useLocaleStore.getState().locale);
  useLocaleStore.subscribe((state, previous) => {
    if (state.locale !== previous.locale) applyDocumentLanguage(state.locale);
  });
  window.addEventListener('languagechange', () => useLocaleStore.getState().refresh());
}
