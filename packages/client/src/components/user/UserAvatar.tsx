import { useAvatarSource } from '../../stores/avatar-cache';

const SIZES = {
  xs: 'h-4 w-4 text-[9px]',
  sm: 'h-8 w-8 text-sm',
  md: 'h-10 w-10 text-base',
  lg: 'h-24 w-24 text-3xl',
} as const;

/** Muted earth tones that keep a white letter readable. */
const TONES = [
  'bg-[#a4553f]',
  'bg-[#5d7a45]',
  'bg-[#3f6f8a]',
  'bg-[#7d5a87]',
  'bg-[#3d7a72]',
  'bg-[#94702e]',
  'bg-[#9b5068]',
  'bg-[#5f6680]',
];

/** A background that stays the same for a name, so people are told apart at a glance. */
export function avatarTone(displayName: string): string {
  let hash = 7;
  for (const character of displayName) hash = (hash * 31 + character.codePointAt(0)!) >>> 0;
  return TONES[hash % TONES.length];
}

/**
 * A member's picture, or the first letter of their name. `hidden` shows the
 * letter even when a picture exists (a profile an administrator warned about).
 */
export function UserAvatar({ displayName, avatarUrl, hidden = false, size = 'md', className = '' }: {
  displayName: string;
  avatarUrl?: string | null;
  hidden?: boolean;
  size?: keyof typeof SIZES;
  className?: string;
}) {
  const source = useAvatarSource(avatarUrl, hidden);
  const base = `${SIZES[size]} shrink-0 rounded-full ${className}`;
  if (source) return <img src={source} alt="" className={`${base} object-cover`} draggable={false} />;
  return (
    <span
      aria-hidden="true"
      className={`${base} ${avatarTone(displayName || '?')} flex items-center justify-center font-semibold text-white`}
    >
      {(displayName || '?').slice(0, 1).toUpperCase()}
    </span>
  );
}
