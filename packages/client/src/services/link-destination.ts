/**
 * Where a Markdown link really goes. Desktop and Android show no address on
 * hover, so a link whose text names one place while its address names another
 * is shown with its destination, and opening it asks first.
 */
export interface LinkDestination {
  /** What the link opens: the host of a web link, the address of a mail link. */
  place: string;
  /** The full destination, with the host as the system opens it. */
  address: string;
  /** The text does not give the destination itself, so the place is shown beside it. */
  masked: boolean;
  /** The text reads like another web or mail address, so opening asks first. */
  misleading: boolean;
}

// Only the start of the text is read; longer text is cut off where it is shown too.
const TEXT_LIMIT = 500;

// Endings that mark a bare name as a web address. Only well-known ones count,
// so file names such as README.md or main.rs are not taken for addresses.
const WEB_ENDINGS = [
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro', 'mobi', 'asia', 'tel', 'jobs', 'travel',
  'app', 'dev', 'page', 'io', 'co', 'ai', 'xyz', 'online', 'site', 'store', 'shop', 'tech', 'cloud', 'live', 'link', 'club',
  'top', 'vip', 'work', 'blog', 'news', 'email', 'world', 'today', 'life', 'space', 'website', 'services', 'support',
  'solutions', 'network', 'digital', 'group', 'company', 'agency', 'bank', 'finance', 'money', 'pay',
  'jp', 'uk', 'us', 'eu', 'de', 'fr', 'es', 'it', 'nl', 'ch', 'se', 'no', 'dk', 'fi', 'ru', 'cn', 'kr', 'tw', 'hk', 'sg',
  'au', 'nz', 'ca', 'br', 'mx', 'in', 'tv', 'me',
];

const LABEL = String.raw`[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`;
const REST = String.raw`[^\s<>"'\x60]*`;
// With a scheme, with www., or a bare name (which may be the domain of a mail address).
const ADDRESS_IN_TEXT = new RegExp([
  String.raw`https?:\/\/${REST}`,
  String.raw`www\.${REST}`,
  String.raw`(?<![\w.-])(?:${LABEL}\.)+(?:${WEB_ENDINGS.join('|')})(?![\w-]|\.\w)(?::\d+)?(?:[/?#]${REST})?`,
].join('|'), 'gi');
// Closing quotes, brackets and sentence marks (including Japanese ones) that end a sentence, not an address.
const TRAILING_PUNCTUATION = /[.,;:!?)\]}>'"\x60\u{201d}\u{2019}\u{3002}\u{3001}\u{ff09}\u{300d}\u{300f}]+$/u;
// Control, zero-width and direction marks.
const INVISIBLE = /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200b}-\u{200f}\u{202a}-\u{202e}\u{2060}-\u{2069}\u{feff}]/gu;
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

function currentPageUrl(): string {
  return typeof location === 'undefined' ? 'https://local.invalid/' : location.href;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function canonicalHost(host: string): string | null {
  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    return null;
  }
}

/** The site a host belongs to, for comparing what the text shows with where the link goes. */
function siteOf(host: string): string {
  return host.replace(/\.$/, '').replace(/^www\./, '');
}

/** The host a mail link writes to: that of the first recipient. */
function mailHost(recipients: string): string | null {
  const first = recipients.split(',')[0];
  return canonicalHost(first.slice(first.lastIndexOf('@') + 1));
}

function hostsIn(text: string): string[] {
  const hosts: string[] = [];
  for (const [found] of text.matchAll(ADDRESS_IN_TEXT)) {
    const address = found.replace(TRAILING_PUNCTUATION, '');
    try {
      hosts.push(new URL(SCHEME.test(address) ? address : `http://${address}`).hostname);
    } catch {
      // Not an address after all.
    }
  }
  return hosts;
}

// Autolinks leave out the scheme (www.example.com) or the slash after a bare host.
function givesDestination(shown: string, href: string, target: URL, recipients: string | null): boolean {
  if (shown === href.trim()) return true;
  if (recipients !== null) return shown === recipients || shown === `mailto:${recipients}`;
  try {
    return new URL(SCHEME.test(shown) ? shown : `${target.protocol}//${shown}`).href === target.href;
  } catch {
    return false;
  }
}

/**
 * `href` has passed safeMarkdownHref. Null for a link within the app, which
 * goes nowhere new.
 */
export function describeLink(href: string, text: string, pageUrl: string = currentPageUrl()): LinkDestination | null {
  let page: URL;
  let target: URL;
  try {
    page = new URL(pageUrl);
    target = new URL(href, page);
  } catch {
    return null;
  }
  const mail = target.protocol === 'mailto:';
  if (!mail && target.protocol !== 'http:' && target.protocol !== 'https:') return null;
  if (!mail && target.origin === page.origin) return null;

  const recipients = mail ? safeDecode(target.pathname) : null;
  // Full-width letters and the like read as the plain ones, so they are compared as such.
  const shown = text.normalize('NFKC').replace(/\s+/g, ' ').trim().slice(0, TEXT_LIMIT);
  const masked = !givesDestination(shown, href, target, recipients);
  const host = recipients === null ? target.hostname : mailHost(recipients);
  const misleading = masked && hostsIn(shown).some((found) => host === null || siteOf(found) !== siteOf(host));
  return { place: recipients ?? target.hostname, address: target.href, masked, misleading };
}

/** Text as shown in a confirmation, without control or direction marks that could reorder what surrounds it. */
export function plainLinkText(text: string, limit = 80): string {
  const plain = text.replace(INVISIBLE, ' ').replace(/\s+/g, ' ').trim();
  return plain.length > limit ? `${plain.slice(0, limit)}…` : plain;
}
