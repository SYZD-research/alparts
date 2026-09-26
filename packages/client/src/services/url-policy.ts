/** Allow navigable Markdown links without permitting active or local schemes. */
export function safeMarkdownHref(href: string | undefined): string | null {
  if (!href || /[\u0000-\u001f\u007f]/.test(href)) return null;
  const trimmed = href.trim();
  if (trimmed.startsWith('//') || trimmed.includes('\\')) return null;
  try {
    const parsed = new URL(trimmed, 'https://local.invalid');
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:'
      ? trimmed
      : null;
  } catch {
    return null;
  }
}
