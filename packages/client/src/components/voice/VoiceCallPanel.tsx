import { useEffect, useRef } from 'react';
import { useAuthStore } from '../../stores/auth.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import {
  getRemoteVoiceStream,
  useVoiceStore,
  type VoiceConnectionQuality,
} from '../../stores/voice.store';

interface Props {
  channelId: string;
}

export function VoiceCallPanel({ channelId }: Props) {
  const status = useVoiceStore((state) => state.status);
  const callChannelId = useVoiceStore((state) => state.channelId);
  const participants = useVoiceStore((state) => state.participants);
  const muted = useVoiceStore((state) => state.muted);
  const mode = useVoiceStore((state) => state.mode);
  const pushToTalkActive = useVoiceStore((state) => state.pushToTalkActive);
  const inputDevices = useVoiceStore((state) => state.inputDevices);
  const outputDevices = useVoiceStore((state) => state.outputDevices);
  const selectedInputId = useVoiceStore((state) => state.selectedInputId);
  const selectedOutputId = useVoiceStore((state) => state.selectedOutputId);
  const quality = useVoiceStore((state) => state.quality);
  const remoteStreamRevision = useVoiceStore((state) => state.remoteStreamRevision);
  const error = useVoiceStore((state) => state.error);
  const join = useVoiceStore((state) => state.join);
  const leave = useVoiceStore((state) => state.leave);
  const setMuted = useVoiceStore((state) => state.setMuted);
  const setMode = useVoiceStore((state) => state.setMode);
  const setPushToTalkActive = useVoiceStore((state) => state.setPushToTalkActive);
  const setInputDevice = useVoiceStore((state) => state.setInputDevice);
  const setOutputDevice = useVoiceStore((state) => state.setOutputDevice);
  const members = useWorkspaceStore((state) => state.members);
  const currentUserId = useAuthStore((state) => state.user?.id);
  const inThisCall = status === 'connected' && callChannelId === channelId;

  useEffect(() => () => {
    const active = useVoiceStore.getState();
    if (active.channelId === channelId) active.leave();
  }, [channelId]);

  useEffect(() => {
    const releasePushToTalk = () => useVoiceStore.getState().setPushToTalkActive(false);
    window.addEventListener('blur', releasePushToTalk);
    return () => window.removeEventListener('blur', releasePushToTalk);
  }, []);

  if (!inThisCall) {
    return (
      <div className="flex min-h-11 items-center justify-between gap-3 border-b border-discord-sidebar bg-discord-sidebar/35 px-4 py-2">
        <div className="min-w-0">
          <p className="text-sm font-medium text-discord-text">音声通話</p>
          <p className="truncate text-xs text-discord-muted">
            {status === 'joining' ? 'マイクを準備しています…' : '最大8人のグループ音声通話'}
          </p>
          {error && <p role="alert" className="mt-1 text-xs text-discord-red">{error}</p>}
        </div>
        <button
          type="button"
          disabled={status === 'joining'}
          onClick={() => void join(channelId)}
          className="shrink-0 rounded bg-discord-green px-3 py-2 text-sm font-medium text-white hover:brightness-110 disabled:cursor-wait disabled:opacity-50"
        >
          {status === 'joining' ? '参加中…' : error ? '再試行' : '🎙 通話に参加'}
        </button>
      </div>
    );
  }

  return (
    <section aria-label="音声通話" className="border-b border-discord-sidebar bg-discord-sidebar/55 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="mr-auto min-w-40">
          <p className="text-sm font-semibold text-discord-green">音声接続済み</p>
          <p className="text-xs text-discord-muted">{qualityLabel(quality)}</p>
        </div>
        <button
          type="button"
          aria-pressed={muted}
          onClick={() => setMuted(!muted)}
          className={`rounded px-3 py-2 text-sm ${muted ? 'bg-discord-red text-white' : 'bg-discord-hover text-discord-text'}`}
        >
          {muted ? '🔇 ミュート解除' : '🎙 ミュート'}
        </button>
        <select
          aria-label="音声送信モード"
          value={mode}
          onChange={(event) => setMode(event.target.value === 'push-to-talk' ? 'push-to-talk' : 'voice-activity')}
          className="rounded bg-discord-input px-2 py-2 text-sm text-discord-text outline-none focus:ring-1 focus:ring-discord-accent"
        >
          <option value="voice-activity">音声検出</option>
          <option value="push-to-talk">プッシュトゥトーク</option>
        </select>
        <button
          type="button"
          onClick={leave}
          className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white hover:brightness-110"
        >
          切断
        </button>
      </div>

      {mode === 'push-to-talk' && (
        <button
          type="button"
          disabled={muted}
          aria-pressed={pushToTalkActive}
          onPointerDown={(event) => {
            event.currentTarget.setPointerCapture(event.pointerId);
            setPushToTalkActive(true);
          }}
          onPointerUp={() => setPushToTalkActive(false)}
          onPointerCancel={() => setPushToTalkActive(false)}
          onKeyDown={(event) => {
            if (!event.repeat && (event.key === ' ' || event.key === 'Enter')) setPushToTalkActive(true);
          }}
          onKeyUp={(event) => {
            if (event.key === ' ' || event.key === 'Enter') setPushToTalkActive(false);
          }}
          className={`mt-3 w-full rounded px-4 py-3 text-sm font-semibold transition-colors disabled:opacity-40 ${
            pushToTalkActive ? 'bg-discord-green text-white' : 'bg-discord-input text-discord-text'
          }`}
        >
          {muted ? 'ミュートを解除してください' : pushToTalkActive ? '送信中 — 離すと停止' : '押している間だけ話す'}
        </button>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        <label className="flex min-w-48 flex-1 items-center gap-2 text-xs text-discord-muted">
          マイク
          <select
            value={selectedInputId}
            onChange={(event) => void setInputDevice(event.target.value)}
            className="min-w-0 flex-1 rounded bg-discord-input px-2 py-1.5 text-discord-text outline-none focus:ring-1 focus:ring-discord-accent"
          >
            <option value="">システム既定</option>
            {inputDevices.filter((device) => device.deviceId !== 'default').map((device) => (
              <option key={device.deviceId} value={device.deviceId}>{device.label}</option>
            ))}
          </select>
        </label>
        {supportsAudioOutputSelection() && (
          <label className="flex min-w-48 flex-1 items-center gap-2 text-xs text-discord-muted">
            出力
            <select
              value={selectedOutputId}
              onChange={(event) => setOutputDevice(event.target.value)}
              className="min-w-0 flex-1 rounded bg-discord-input px-2 py-1.5 text-discord-text outline-none focus:ring-1 focus:ring-discord-accent"
            >
              <option value="">システム既定</option>
              {outputDevices.filter((device) => device.deviceId !== 'default').map((device) => (
                <option key={device.deviceId} value={device.deviceId}>{device.label}</option>
              ))}
            </select>
          </label>
        )}
      </div>

      <ul aria-label="通話参加者" className="mt-3 flex flex-wrap gap-2">
        {participants.map((participant) => {
          const displayName = members.find((member) => member.userId === participant.userId)?.user.displayName ?? 'ユーザー';
          const isSelf = participant.participantId === useVoiceStore.getState().self?.participantId;
          return (
            <li
              key={participant.participantId}
              className={`rounded-full border px-3 py-1 text-xs ${
                participant.speaking
                  ? 'border-discord-green bg-discord-green/15 text-white'
                  : 'border-discord-hover text-discord-muted'
              }`}
            >
              {participant.muted ? '🔇' : participant.speaking ? '●' : '○'} {displayName}
              {isSelf || participant.userId === currentUserId ? '（自分）' : ''}
            </li>
          );
        })}
      </ul>
      {error && <p role="alert" className="mt-2 text-xs text-discord-red">{error}</p>}

      {participants.map((participant) => participant.participantId === useVoiceStore.getState().self?.participantId ? null : (
        <RemoteVoiceAudio
          key={participant.participantId}
          participantId={participant.participantId}
          outputDeviceId={selectedOutputId}
          revision={remoteStreamRevision}
        />
      ))}
    </section>
  );
}

function RemoteVoiceAudio({
  participantId,
  outputDeviceId,
  revision,
}: {
  participantId: string;
  outputDeviceId: string;
  revision: number;
}) {
  const ref = useRef<HTMLAudioElement>(null);

  useEffect(() => {
    const audio = ref.current;
    if (!audio) return;
    audio.srcObject = getRemoteVoiceStream(participantId);
    if (audio.srcObject) void audio.play().catch(() => undefined);
    return () => {
      audio.srcObject = null;
    };
  }, [participantId, revision]);

  useEffect(() => {
    const audio = ref.current;
    if (audio && typeof audio.setSinkId === 'function') {
      void audio.setSinkId(outputDeviceId).catch(() => undefined);
    }
  }, [outputDeviceId]);

  return <audio ref={ref} autoPlay playsInline className="sr-only" />;
}

function supportsAudioOutputSelection(): boolean {
  return typeof HTMLMediaElement !== 'undefined' && 'setSinkId' in HTMLMediaElement.prototype;
}

function qualityLabel(quality: VoiceConnectionQuality): string {
  if (quality === 'good') return '品質 良好';
  if (quality === 'fair') return '品質 普通';
  if (quality === 'poor') return '品質 低下';
  return '接続確認中';
}
