import { useAvatarSource } from '../../stores/avatar-cache';

const SIZES = {
  xs: 'h-4 w-4 text-[9px]',
  sm: 'h-8 w-8 text-sm',
  md: 'h-10 w-10 text-base',
  lg: 'h-24 w-24 text-3xl',
} as const;

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
    <span aria-hidden="true" className={`${base} flex items-center justify-center bg-discord-accent font-bold text-white`}>
      {(displayName || '?').slice(0, 1).toUpperCase()}
    </span>
  );
}
