export const VOICE_PRESENCE_ROOM_PREFIX = 'voice-presence:';

export function voicePresenceRoom(channelId: string): string {
  return `${VOICE_PRESENCE_ROOM_PREFIX}${channelId}`;
}
