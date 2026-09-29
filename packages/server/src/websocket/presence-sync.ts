import type { UserStatusType } from '@alparts/shared';

export interface PresenceStore {
  /** Live sockets currently in the user's identity room. */
  countConnections(userId: string): Promise<number>;
  readStatus(userId: string): Promise<UserStatusType | null>;
  writeStatus(userId: string, status: UserStatusType): Promise<void>;
  broadcast(userId: string, status: UserStatusType): Promise<void>;
}

/**
 * Presence is derived from live connections, one user at a time. Connects,
 * disconnects and explicit status changes for the same user run strictly in
 * order and each re-reads the connection count, so an overlapping reconnect
 * can never leave a connected user recorded (and broadcast) as offline.
 */
export class PresenceSynchronizer {
  readonly #queues = new Map<string, Promise<void>>();

  constructor(private readonly store: PresenceStore) {}

  /** Recompute after a socket connected or disconnected. */
  sync(userId: string): Promise<void> {
    return this.#serialize(userId, async () => {
      const connected = await this.store.countConnections(userId) > 0;
      const current = (await this.store.readStatus(userId)) ?? 'offline';
      // A connected user keeps an explicitly chosen idle/dnd status.
      const next: UserStatusType = !connected ? 'offline' : current === 'offline' ? 'online' : current;
      if (next !== current) await this.#apply(userId, next);
    });
  }

  /** An explicit status chosen by a connected client. */
  choose(userId: string, status: UserStatusType): Promise<void> {
    return this.#serialize(userId, async () => {
      if (await this.store.countConnections(userId) === 0) return;
      if ((await this.store.readStatus(userId)) !== status) await this.#apply(userId, status);
    });
  }

  async #apply(userId: string, status: UserStatusType): Promise<void> {
    await this.store.writeStatus(userId, status);
    await this.store.broadcast(userId, status);
  }

  #serialize(userId: string, operation: () => Promise<void>): Promise<void> {
    const previous = this.#queues.get(userId) ?? Promise.resolve();
    const next = previous.catch(() => undefined).then(operation);
    const tail = next.catch(() => undefined);
    this.#queues.set(userId, tail);
    void tail.then(() => {
      if (this.#queues.get(userId) === tail) this.#queues.delete(userId);
    });
    return next;
  }
}
