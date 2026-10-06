export class DownloadLeaseState {
  private total = 0;
  private readonly perUser = new Map<string, number>();

  constructor(
    private readonly maxPerUser = 2,
    private readonly maxTotal = 8,
  ) {}

  acquire(userId: string): (() => void) | null {
    const current = this.perUser.get(userId) ?? 0;
    if (!userId || current >= this.maxPerUser || this.total >= this.maxTotal) return null;
    this.total += 1;
    this.perUser.set(userId, current + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.total -= 1;
      const remaining = (this.perUser.get(userId) ?? 1) - 1;
      if (remaining <= 0) this.perUser.delete(userId);
      else this.perUser.set(userId, remaining);
    };
  }
}

const downloads = new DownloadLeaseState();

export function acquireDownloadLease(userId: string): (() => void) | null {
  return downloads.acquire(userId);
}

// Avatars are read whole before they are sent, so these bound the memory held
// for clients that read slowly, not object-storage capacity.
export const MAX_AVATAR_DOWNLOADS_PER_USER = 4;
export const MAX_AVATAR_DOWNLOADS = 32;
const avatarDownloads = new DownloadLeaseState(MAX_AVATAR_DOWNLOADS_PER_USER, MAX_AVATAR_DOWNLOADS);

export function acquireAvatarDownloadLease(userId: string): (() => void) | null {
  return avatarDownloads.acquire(userId);
}
