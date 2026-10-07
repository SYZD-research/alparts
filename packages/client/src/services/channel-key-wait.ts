export const CHANNEL_KEY_DELIVERY_PENDING = 'CHANNEL_KEY_DELIVERY_PENDING';

/**
 * Why this device cannot write to a channel yet:
 * - `waiting`: it is not in the channel's group yet; a member adds it.
 * - `rejoining`: it could not read an update and asked to be added again.
 *   Keys it already had stay readable.
 * - `genesis-waiting`: the channel's first group waits for other devices.
 *   Earlier history stays readable.
 * - `unavailable`: it asked to be added again too often; waiting no longer
 *   helps. Earlier history stays readable.
 */
export type ChannelKeyWaitReason = 'waiting' | 'rejoining' | 'genesis-waiting' | 'unavailable';

export interface ChannelKeyWait {
  reason: ChannelKeyWaitReason;
  /** The server lets this device start the conversation again without its history. */
  freshStartAvailable: boolean;
}

const WAIT_REASONS: ReadonlySet<string> = new Set<ChannelKeyWaitReason>([
  'waiting',
  'rejoining',
  'genesis-waiting',
  'unavailable',
]);

/**
 * This device is authorized, but another device must add it to the channel's
 * group first. Treat this as recoverable availability, never as a
 * cryptographic verification failure or a reason to use plaintext.
 */
export class ChannelKeyDeliveryPendingError extends Error {
  readonly code = CHANNEL_KEY_DELIVERY_PENDING;

  constructor(
    readonly reason: ChannelKeyWaitReason = 'waiting',
    readonly freshStartAvailable = false,
  ) {
    super(CHANNEL_KEY_DELIVERY_PENDING);
    this.name = 'ChannelKeyDeliveryPendingError';
  }

  get wait(): ChannelKeyWait {
    return { reason: this.reason, freshStartAvailable: this.freshStartAvailable };
  }
}

export function isChannelKeyDeliveryPendingError(
  error: unknown,
): error is ChannelKeyDeliveryPendingError {
  return error instanceof ChannelKeyDeliveryPendingError
    || (typeof error === 'object'
      && error !== null
      && (error as { code?: unknown }).code === CHANNEL_KEY_DELIVERY_PENDING);
}

/** The waiting state an error describes, or null for any other error. */
export function channelKeyWait(error: unknown): ChannelKeyWait | null {
  if (!isChannelKeyDeliveryPendingError(error)) return null;
  const candidate = error as Partial<ChannelKeyDeliveryPendingError>;
  return {
    reason: typeof candidate.reason === 'string' && WAIT_REASONS.has(candidate.reason)
      ? candidate.reason as ChannelKeyWaitReason
      : 'waiting',
    freshStartAvailable: candidate.freshStartAvailable === true,
  };
}
