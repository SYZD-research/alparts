import { vi } from 'vitest';

// Tests assert the Japanese source text on every machine. The language is
// fixed before the locale store is created, because server-side rendering
// reads the store's initial state rather than later updates.
vi.stubGlobal('navigator', { ...globalThis.navigator, language: 'ja-JP', languages: ['ja-JP'] });
const { useLocaleStore } = await import('./i18n');
useLocaleStore.setState({ preference: 'ja', locale: 'ja' });
