import { isDeviceSequence, MAX_SEEN_HEADS, type Message, type SignedEventHead } from '@alparts/shared';
import { hasSequencedEnvelope } from './message-projector';

/**
 * Numbering this device's events in a channel (message protocol v6).
 *
 * The server refuses a number the device already used, so a number is used
 * at most once by an honest server. The device must never sign two events under
 * one number either: a server that stored both could show one to some members
 * and the other to the rest, and neither would see a gap. So the next number
 * is above every number this device knows was stored (its own events it has
 * received, and the replies to its writes), and the server's word is taken
 * only to go higher (when it refuses a number as already used). The highest
 * known number is kept in the browser so it survives a restart.
 */

const STORAGE_PREFIX = 'alparts.device-sequence.v1:';
const MAX_REMEMBERED_CHANNELS = 512;
/**
 * How far above the highest stored number the server may ask this device to
 * go. Its honest request is the number after the device's last stored event,
 * which is at most a few writes (another tab's, or one whose answer was
 * lost) above what this device knows; a server asking for much more would
 * only open gaps, or run the numbers out.
 */
const MAX_EXPECTED_JUMP = 1_000;

interface DeviceScope {
  userId: string;
  deviceId: string;
}

/** Highest stored number per device scope and channel. */
const storedHigh = new Map<string, Map<string, number>>();
/** The number the server asked for after a refusal, per device scope and channel. */
const serverExpected = new Map<string, Map<string, number>>();

function scopeKey(scope: DeviceScope): string {
  return `${scope.userId}:${scope.deviceId}`;
}

/**
 * The highest stored number per channel, as this tab knows it merged with
 * what the browser keeps (another tab of the same device may have written
 * since). Numbers only go up.
 */
function remembered(scope: DeviceScope): Map<string, number> {
  const key = scopeKey(scope);
  const channels = storedHigh.get(key) ?? new Map<string, number>();
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_PREFIX + key);
    const parsed = raw ? JSON.parse(raw) as unknown : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [channelId, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (isDeviceSequence(value) && (channels.get(channelId) ?? 0) < value) channels.set(channelId, value);
      }
    }
  } catch {
    // Storage may be unavailable (private window, blocked site data); the
    // channel's own events and the server's refusals still keep numbers apart.
  }
  storedHigh.set(key, channels);
  return channels;
}

function persist(scope: DeviceScope, channels: Map<string, number>): void {
  while (channels.size > MAX_REMEMBERED_CHANNELS) channels.delete(channels.keys().next().value!);
  try {
    globalThis.localStorage?.setItem(STORAGE_PREFIX + scopeKey(scope), JSON.stringify(Object.fromEntries(channels)));
  } catch {
    // See remembered().
  }
}

/** Record that this device's event with this number is stored in the channel. */
export function noteStoredSequence(scope: DeviceScope, channelId: string, deviceSeq: number): void {
  if (!isDeviceSequence(deviceSeq)) return;
  const channels = remembered(scope);
  if ((channels.get(channelId) ?? 0) >= deviceSeq) return;
  // Most recently written channels stay when the list is trimmed.
  channels.delete(channelId);
  channels.set(channelId, deviceSeq);
  persist(scope, channels);
}

/** Record the number the server asked for when it refused one (only ever raises the next number). */
export function noteExpectedSequence(scope: DeviceScope, channelId: string, expected: number | null): void {
  if (expected === null || !isDeviceSequence(expected)) return;
  if (expected > (remembered(scope).get(channelId) ?? 0) + MAX_EXPECTED_JUMP) return;
  const key = scopeKey(scope);
  const channels = serverExpected.get(key) ?? new Map<string, number>();
  if ((channels.get(channelId) ?? 0) < expected) channels.set(channelId, expected);
  serverExpected.set(key, channels);
}

/**
 * The number for this device's next event in the channel: one above the
 * highest it knows was stored (its own verified events in the window count),
 * or the server's request if that is higher.
 */
export function nextDeviceSequence(scope: DeviceScope, channelId: string, events: readonly Message[]): number {
  let high = remembered(scope).get(channelId) ?? 0;
  for (const event of events) {
    if (event.deviceId === scope.deviceId && hasSequencedEnvelope(event) && (event.deviceSeq ?? 0) > high) high = event.deviceSeq!;
  }
  if (high > 0) noteStoredSequence(scope, channelId, high);
  const expected = serverExpected.get(scopeKey(scope))?.get(channelId) ?? 0;
  return Math.max(high + 1, expected);
}

/**
 * The newest event of each other device in the window, newest first, at
 * most `limit` devices: what a new event names as seen. Only events whose v6
 * signature verified count, so an event never names what the server made up.
 */
export function seenHeadsOf(events: readonly Message[], ownDeviceId: string, limit = 1): SignedEventHead[] {
  const heads: SignedEventHead[] = [];
  const devices = new Set<string>([ownDeviceId]);
  for (let index = events.length - 1; index >= 0 && heads.length < Math.min(limit, MAX_SEEN_HEADS); index -= 1) {
    const event = events[index];
    if (!event.deviceId || devices.has(event.deviceId) || !hasSequencedEnvelope(event)) continue;
    devices.add(event.deviceId);
    heads.push({ deviceId: event.deviceId, deviceSeq: event.deviceSeq!, idempotencyKey: event.idempotencyKey });
  }
  return heads;
}

/**
 * Drop what this tab holds in memory (sign-out). The highest stored numbers
 * kept in the browser stay on purpose: the device must not sign a number
 * again after the next sign-in. They hold channel and device ids and
 * counters only, nothing of the messages.
 */
export function resetDeviceSequences(): void {
  storedHigh.clear();
  serverExpected.clear();
}
