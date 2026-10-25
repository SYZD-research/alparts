import type { ReactNode } from 'react';

const dot = (cx: number) => <circle cx={cx} cy="12" r="1.4" fill="currentColor" stroke="none" />;

const paths = {
  announcement: <><path d="M4 9.5h3.5L16 5v14l-8.5-4.5H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1z" /><path d="M7.5 14.5 9 20h2.5M19.5 9.5a3 3 0 0 1 0 5" /></>,
  at: <><circle cx="12" cy="12" r="3.5" /><path d="M15.5 12v1.25a2.75 2.75 0 0 0 5.5 0V12a9 9 0 1 0-3.5 7.1" /></>,
  bellOff: <><path d="M9.5 19a2.5 2.5 0 0 0 5 0" /><path d="M8.1 5.2A5.5 5.5 0 0 1 17.5 9v3.6l1.5 2.9M6.5 9v3.6L5 16h11" /><path d="m4 4 16 16" /></>,
  bookmark: <path d="M7 3.5h10a1 1 0 0 1 1 1v16l-6-4.25-6 4.25v-16a1 1 0 0 1 1-1z" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  chevronDown: <path d="m6 9 6 6 6-6" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  cornerReply: <><path d="M5 5v5.5a4 4 0 0 0 4 4h10" /><path d="m15 10.5 4 4-4 4" /></>,
  file: <><path d="M14 3.5H7.5A1.5 1.5 0 0 0 6 5v14a1.5 1.5 0 0 0 1.5 1.5h9A1.5 1.5 0 0 0 18 19V7.5z" /><path d="M14 3.5v4h4M9 13h6M9 16.5h4" /></>,
  forum: <><path d="M4.5 4.5h10A1.5 1.5 0 0 1 16 6v6a1.5 1.5 0 0 1-1.5 1.5H9l-3.5 3v-3h-1A1.5 1.5 0 0 1 3 12V6a1.5 1.5 0 0 1 1.5-1.5z" /><path d="M16.5 9h3A1.5 1.5 0 0 1 21 10.5v6a1.5 1.5 0 0 1-1.5 1.5h-1v3L15 18h-4.5A1.5 1.5 0 0 1 9 16.5v-1" /></>,
  globe: <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.4 2.3 3.6 5.1 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.1-3.6-8.5s1.2-6.2 3.6-8.5z" /></>,
  hash: <path d="M4.5 9h15M4.5 15h15M10 3.5 8 20.5M16 3.5l-2 17" />,
  key: <><circle cx="8" cy="15.5" r="4" /><path d="m11 12.5 8.5-8.5M16.5 7 19 9.5M14 9.5l2 2" /></>,
  link: <><path d="M10.5 13.5a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1 1" /><path d="M13.5 10.5a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1-1" /></>,
  logout: <><path d="M10 4.5H6A1.5 1.5 0 0 0 4.5 6v12A1.5 1.5 0 0 0 6 19.5h4" /><path d="m15 8 4 4-4 4M19 12H9.5" /></>,
  members: <><circle cx="9" cy="8.5" r="3.25" /><path d="M3.5 19.5v-.75a5.5 5.5 0 0 1 11 0v.75" /><path d="M15.5 5.4a3.25 3.25 0 0 1 0 6.2M17.5 14.2a5.5 5.5 0 0 1 3 4.6v.7" /></>,
  messagePlus: <><path d="M5.5 4.5h13A1.5 1.5 0 0 1 20 6v9a1.5 1.5 0 0 1-1.5 1.5H10L6 20v-3.5h-.5A1.5 1.5 0 0 1 4 15V6a1.5 1.5 0 0 1 1.5-1.5z" /><path d="M12 8v5M9.5 10.5h5" /></>,
  mic: <><rect x="9" y="3.5" width="6" height="10.5" rx="3" /><path d="M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5v3" /></>,
  micOff: <><rect x="9" y="3.5" width="6" height="10.5" rx="3" /><path d="M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5v3" /><path d="m4 4 16 16" /></>,
  more: <>{dot(5.5)}{dot(12)}{dot(18.5)}</>,
  paperclip: <path d="m19.5 11.5-7.4 7.4a4.6 4.6 0 0 1-6.5-6.5l7.8-7.8a3 3 0 0 1 4.3 4.3l-7.7 7.7a1.5 1.5 0 0 1-2.1-2.1l7.1-7.1" />,
  pencil: <><path d="M4.5 19.5h3.75L18.6 9.15a2.65 2.65 0 0 0-3.75-3.75L4.5 15.75z" /><path d="m13.5 6.75 3.75 3.75" /></>,
  pin: <path d="M9 3.5h6M10 3.5v5L6.5 13h11L14 8.5v-5M12 13v7.5" />,
  plus: <path d="M12 5v14M5 12h14" />,
  reply: <><path d="m9.5 6.5-5 5 5 5" /><path d="M4.5 11.5h9a6 6 0 0 1 6 6v1" /></>,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></>,
  send: <path d="M20.5 3.5 10 14M20.5 3.5 14 20.5l-4-6.5-6.5-4z" />,
  settings: <><path d="M10.16 5.14 10.55 2.81A9.3 9.3 0 0 1 13.45 2.81L13.84 5.14A7.1 7.1 0 0 1 15.55 5.85L17.47 4.48A9.3 9.3 0 0 1 19.52 6.53L18.15 8.45A7.1 7.1 0 0 1 18.86 10.16L21.19 10.55A9.3 9.3 0 0 1 21.19 13.45L18.86 13.84A7.1 7.1 0 0 1 18.15 15.55L19.52 17.47A9.3 9.3 0 0 1 17.47 19.52L15.55 18.15A7.1 7.1 0 0 1 13.84 18.86L13.45 21.19A9.3 9.3 0 0 1 10.55 21.19L10.16 18.86A7.1 7.1 0 0 1 8.45 18.15L6.53 19.52A9.3 9.3 0 0 1 4.48 17.47L5.85 15.55A7.1 7.1 0 0 1 5.14 13.84L2.81 13.45A9.3 9.3 0 0 1 2.81 10.55L5.14 10.16A7.1 7.1 0 0 1 5.85 8.45L4.48 6.53A9.3 9.3 0 0 1 6.53 4.48L8.45 5.85A7.1 7.1 0 0 1 10.16 5.14Z" /><circle cx="12" cy="12" r="2.8" /></>,
  shield: <><path d="M12 3.5 5 6.2v5.3c0 4.3 2.9 7.9 7 9 4.1-1.1 7-4.7 7-9V6.2z" /><path d="m9.2 12 2 2 3.6-3.8" /></>,
  sliders: <><path d="M4 6h8M16 6h4M4 12h2M10 12h10M4 18h10M18 18h2" /><circle cx="14" cy="6" r="2" /><circle cx="8" cy="12" r="2" /><circle cx="16" cy="18" r="2" /></>,
  trash: <path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l.8 12.1a1.5 1.5 0 0 0 1.5 1.4h6.4a1.5 1.5 0 0 0 1.5-1.4L17.5 7M10 11v5.5M14 11v5.5" />,
  user: <><circle cx="12" cy="8" r="3.75" /><path d="M4.5 20a7.5 7.5 0 0 1 15 0" /></>,
  voice: <><path d="M11 5.5 6.5 9H4a.5.5 0 0 0-.5.5v5a.5.5 0 0 0 .5.5h2.5l4.5 3.5z" /><path d="M15.5 9a4.2 4.2 0 0 1 0 6M18.5 6.2a8.2 8.2 0 0 1 0 11.6" /></>,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof paths;

/**
 * A line icon in the current text colour. It is decorative: the control it
 * sits in carries the name screen readers announce.
 */
export function Icon({ name, size = 18, filled = false, className = '' }: {
  name: IconName;
  size?: number;
  filled?: boolean;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
    >
      {paths[name]}
    </svg>
  );
}
