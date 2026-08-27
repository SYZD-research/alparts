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

  capture(channelId: string): ChannelKeyScopeToken {
    if (this.blocked.has(channelId)) throw new Error('Channel key scope is revoked');
    return {
      channelId,
      lifecycle: this.lifecycle,
      generation: this.generations.get(channelId) || 0,
    };
  }

  isCurrent(token: ChannelKeyScopeToken): boolean {
    return token.lifecycle === this.lifecycle
      && !this.blocked.has(token.channelId)
      && token.generation === (this.generations.get(token.channelId) || 0);
  }

  assertCurrent(token: ChannelKeyScopeToken): void {
    if (!this.isCurrent(token)) throw new Error('Channel key scope changed during operation');
  }

  invalidate(channelId: string): void {
    this.generations.set(channelId, (this.generations.get(channelId) || 0) + 1);
    this.blocked.add(channelId);
  }

  restore(channelId: string): void {
    if (!this.blocked.delete(channelId)) return;
    this.generations.set(channelId, (this.generations.get(channelId) || 0) + 1);
  }

  reset(): void {
    this.lifecycle += 1;
    this.generations.clear();
    this.blocked.clear();
  }
}
