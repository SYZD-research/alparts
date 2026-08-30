export interface ChannelKeyScopeToken {
  readonly channelId: string;
  readonly lifecycle: number;
  readonly generation: number;
}

/**
 * Guards asynchronous channel-key work against authorization revocation.
 * Invalidated scopes stay blocked until a fresh authorized channel-list
 * response explicitly restores them.
 */
export class ChannelKeyScopeGuard {
  private lifecycle = 0;
  private readonly generations = new Map<string, number>();
  private readonly blocked = new Set<string>();
  private readonly allowedAfterGlobalBlock = new Set<string>();
  private denyByDefault = false;

  constructor(private readonly maxTrackedChannels = 20_000) {
    if (!Number.isSafeInteger(maxTrackedChannels) || maxTrackedChannels < 1) {
      throw new Error('Invalid channel-key scope limit');
    }
  }

  capture(channelId: string): ChannelKeyScopeToken {
    if (!this.isAllowed(channelId)) throw new Error('Channel key scope is revoked');
    return {
      channelId,
      lifecycle: this.lifecycle,
      generation: this.generations.get(channelId) || 0,
    };
  }

  isCurrent(token: ChannelKeyScopeToken): boolean {
    return token.lifecycle === this.lifecycle
      && this.isAllowed(token.channelId)
      && token.generation === (this.generations.get(token.channelId) || 0);
  }

  assertCurrent(token: ChannelKeyScopeToken): void {
    if (!this.isCurrent(token)) throw new Error('Channel key scope changed during operation');
  }

  invalidate(channelId: string): void {
    if (this.denyByDefault) {
      // Default denial needs no entry for every historical revoked channel.
      // Advancing the lifecycle invalidates work captured before this event.
      this.lifecycle += 1;
      this.allowedAfterGlobalBlock.delete(channelId);
      this.generations.clear();
      return;
    }
    if (!this.generations.has(channelId) && this.generations.size >= this.maxTrackedChannels) {
      // Historical channel churn must not grow this map forever. Losing exact
      // history switches to a stricter default-deny mode until a fresh,
      // authorized channel response explicitly restores each live scope.
      this.lifecycle += 1;
      this.generations.clear();
      this.blocked.clear();
      this.allowedAfterGlobalBlock.clear();
      this.denyByDefault = true;
      return;
    }
    this.generations.set(channelId, (this.generations.get(channelId) || 0) + 1);
    this.blocked.add(channelId);
  }

  restore(channelId: string): void {
    if (this.denyByDefault) {
      if (
        !this.allowedAfterGlobalBlock.has(channelId)
        && this.allowedAfterGlobalBlock.size >= this.maxTrackedChannels
      ) return;
      this.allowedAfterGlobalBlock.add(channelId);
      return;
    }
    if (!this.blocked.delete(channelId)) return;
    this.generations.set(channelId, (this.generations.get(channelId) || 0) + 1);
  }

  reset(): void {
    this.lifecycle += 1;
    this.generations.clear();
    this.blocked.clear();
    this.allowedAfterGlobalBlock.clear();
    this.denyByDefault = false;
  }

  private isAllowed(channelId: string): boolean {
    return this.denyByDefault
      ? this.allowedAfterGlobalBlock.has(channelId)
      : !this.blocked.has(channelId);
  }
}
