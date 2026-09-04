import { useEffect, useMemo } from 'react';
import { getSocket } from '../services/socket';
import {
  parseVoiceChannelPresence,
  parseVoiceWatchResult,
} from '../services/voice-signal-model';
import { useChannelStore } from '../stores/channel.store';
import { useVoiceStore } from '../stores/voice.store';

/** Keep the sidebar's voice-channel occupants current without joining a call. */
export function useVoiceChannelPresence(): void {
  const channels = useChannelStore((state) => state.channels);
  const channelIds = useMemo(
    () => channels.filter((channel) => channel.type === 'voice').map((channel) => channel.id).sort(),
    [channels],
  );
  const scopeKey = channelIds.join(',');

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    let disposed = false;
    let requestVersion = 0;

    const watch = () => {
      const version = ++requestVersion;
      socket.timeout(5_000).emit(
        'voice:watch',
        { channelIds },
        (error: Error | null, value?: unknown) => {
          if (disposed || version !== requestVersion || error) return;
          const result = parseVoiceWatchResult(value);
          if (!result?.ok || result.channels.some((channel) => !channelIds.includes(channel.channelId))) return;
          useVoiceStore.getState().replaceChannelParticipants(channelIds, result.channels);
        },
      );
    };
    const onPresenceChanged = (value: unknown) => {
      const presence = parseVoiceChannelPresence(value);
      if (!presence || !channelIds.includes(presence.channelId)) return;
      useVoiceStore.getState().setChannelParticipants(presence.channelId, presence.participants);
    };
    const clearDisconnectedPresence = () => {
      useVoiceStore.getState().replaceChannelParticipants(channelIds, []);
    };

    socket.on('connect', watch);
    socket.on('disconnect', clearDisconnectedPresence);
    socket.on('voice:participants-changed', onPresenceChanged);
    if (socket.connected) watch();
    return () => {
      disposed = true;
      requestVersion += 1;
      socket.off('connect', watch);
      socket.off('disconnect', clearDisconnectedPresence);
      socket.off('voice:participants-changed', onPresenceChanged);
      useVoiceStore.getState().replaceChannelParticipants(channelIds, []);
      if (socket.connected) socket.emit('voice:watch', { channelIds: [] });
    };
  // `scopeKey` intentionally represents the stable, sorted set of channel ids.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeKey]);
}
