import { isDeviceSequence, type Message } from '@alparts/shared';
import { hasSequencedEnvelope, keyPrefixOf, type RememberedHead } from './message-projector';

/**
 * What this browser has received of each channel (message protocol v6): for
 * each device, the highest number of its events that verified here and the
 * start of that event's signed key. The server never removes an event, so
 * when the channel is loaded again, a device whose newest held event is
 * below what was received before had events taken away, and an event held
 * under a remembered number with another key was swapped (formal model M10,
 * MO-rollback). Only verified events are remembered, so the server cannot
 * plant a number here. Nothing of the messages themselves is kept.
 */

const STORAGE_PREFIX = 'alparts.channel-heads.v1:';
const MAX_CHANNELS = 128;
const MAX_DEVICES_PER_CHANNEL = 32;
/** As keyPrefixOf cuts it. */
const KEY_PREFIX_LENGTH = 12;

type ChannelHeads = Map<string, RememberedHead>;

const memory = new Map<string, Map<string, ChannelHeads>>();

function load(userId: string): Map<string, ChannelHeads> {
  let channels = memory.get(userId);
  if (channels) return channels;
  channels = new Map();
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_PREFIX + userId);
    const parsed = raw ? JSON.parse(raw) as unknown : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [channelId, devices] of Object.entries(parsed as Record<string, unknown>)) {
        if (!devices || typeof devices !== 'object' || Array.isArray(devices)) continue;
        const heads: ChannelHeads = new Map();
        for (const [deviceId, value] of Object.entries(devices as Record<string, unknown>)) {
          if (!Array.isArray(value) || value.length !== 2) continue;
          const [deviceSeq, keyPrefix] = value as unknown[];
          if (isDeviceSequence(deviceSeq) && typeof keyPrefix === 'string' && keyPrefix.length > 0 && keyPrefix.length <= KEY_PREFIX_LENGTH) {
            heads.set(deviceId, { deviceSeq, keyPrefix });
          }
        }
        if (heads.size > 0) channels.set(channelId, heads);
      }
    }
  } catch {
    // Storage may be unavailable; the channel is then checked within what is loaded.
  }
  memory.set(userId, channels);
  return channels;
}

function persist(userId: string, channels: Map<string, ChannelHeads>): void {
  while (channels.size > MAX_CHANNELS) channels.delete(channels.keys().next().value!);
  const stored = Object.fromEntries([...channels].map(([channelId, heads]) => [
    channelId,
    Object.fromEntries([...heads].map(([deviceId, head]) => [deviceId, [head.deviceSeq, head.keyPrefix]])),
  ]));
  try {
    globalThis.localStorage?.setItem(STORAGE_PREFIX + userId, JSON.stringify(stored));
  } catch {
    // See load().
  }
}

/** The newest event received from each device of the channel, as remembered. */
export function rememberedHeads(userId: string, channelId: string): ReadonlyMap<string, RememberedHead> {
  return load(userId).get(channelId) ?? new Map();
}

/**
 * Remember the newest verified v6 event of each device among these. Numbers
 * only go up; devices written to longest ago are forgotten first.
 */
export function rememberHeads(userId: string, channelId: string, events: readonly Message[]): void {
  const channels = load(userId);
  const heads: ChannelHeads = channels.get(channelId) ?? new Map();
  let changed = false;
  for (const event of events) {
    if (!event.deviceId || !hasSequencedEnvelope(event) || !isDeviceSequence(event.deviceSeq)) continue;
    const known = heads.get(event.deviceId);
    if (known && known.deviceSeq >= event.deviceSeq) continue;
    heads.delete(event.deviceId);
    heads.set(event.deviceId, { deviceSeq: event.deviceSeq, keyPrefix: keyPrefixOf(event.idempotencyKey) });
    changed = true;
  }
  if (!changed) return;
  while (heads.size > MAX_DEVICES_PER_CHANNEL) heads.delete(heads.keys().next().value!);
  channels.delete(channelId);
  channels.set(channelId, heads);
  persist(userId, channels);
}

/**
 * Drop what this tab holds in memory (sign-out). The copy kept in the browser
 * stays on purpose, so the next session can still tell what was received:
 * channel and device ids, numbers and the start of signed keys, nothing of
 * the messages.
 */
export function resetChannelMemory(): void {
  memory.clear();
}
