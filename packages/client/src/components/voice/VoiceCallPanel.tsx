import { useEffect, useRef } from 'react';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useChannelStore } from '../../stores/channel.store';
import {
  getRemoteVoiceStream,
  useVoiceStore,
  type VoiceConnectionQuality,
} from '../../stores/voice.store';

/** Persistent call controls live in the sidebar so text-channel navigation cannot unmount them. */
export function VoiceCallPanel() {
  const status = useVoiceStore((state) => state.status);
  const channelId = useVoiceStore((state) => state.channelId);
  const participants = useVoiceStore((state) => state.participants);
  const self = useVoiceStore((state) => state.self);
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
  const channelName = useChannelStore((state) => (
    state.channels.find((channel) => channel.id === channelId)?.name
  ));
  const members = useWorkspaceStore((state) => state.members);

  useEffect(() => {
    const releasePushToTalk = () => useVoiceStore.getState().setPushToTalkActive(false);
    window.addEventListener('blur', releasePushToTalk);
    return () => window.removeEventListener('blur', releasePushToTalk);
  }, []);

  if (status === 'idle' || !channelId) return null;
  if (status !== 'connected') {
    return (
      <section aria-label="音声通話" className="border-t border-discord-bg bg-discord-bg/70 p-2">
        <p className={`truncate text-xs font-semibold ${status === 'joining' ? 'text-discord-green' : 'text-discord-red'}`}>
          {status === 'joining' ? '音声チャンネルに参加中…' : '音声チャンネルに参加できませんでした'}
        </p>
        <p className="mt-0.5 truncate text-xs text-discord-muted">{channelName || '音声チャンネル'}</p>
        {error && <p role="alert" className="mt-1 text-xs text-discord-red">{error}</p>}
        <div className="mt-2 flex gap-1">
          {status === 'error' && (
            <button type="button" onClick={() => void join(channelId)} className="flex-1 rounded bg-discord-green px-2 py-1.5 text-xs font-medium text-white">
              再試行
            </button>
          )}
          <button type="button" onClick={leave} className="flex-1 rounded bg-discord-hover px-2 py-1.5 text-xs text-discord-text">
            {status === 'joining' ? 'キャンセル' : '閉じる'}
          </button>
        </div>
      </section>
    );
  }

  return (
    <section aria-label="音声通話" className="border-t border-discord-bg bg-discord-bg/70 p-2">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-xs font-semibold text-discord-green">音声接続済み</p>
          <p className="truncate text-[11px] text-discord-muted">{channelName || '音声チャンネル'}・{qualityLabel(quality)}</p>
        </div>
        <button
          type="button"
          aria-pressed={muted}
          aria-label={muted ? 'ミュートを解除' : 'ミュート'}
          title={muted ? 'ミュートを解除' : 'ミュート'}
          onClick={() => setMuted(!muted)}
          className={`rounded px-2 py-1.5 text-sm ${muted ? 'bg-discord-red text-white' : 'bg-discord-hover text-discord-text'}`}
        >
          {muted ? '🔇' : '🎙'}
        </button>
        <button type="button" onClick={leave} className="rounded bg-discord-red px-2 py-1.5 text-xs font-medium text-white">
          切断
        </button>
      </div>

      <ul aria-label="通話参加者" className="mt-2 flex flex-wrap gap-1">
        {participants.map((participant) => {
          const displayName = members.find((member) => member.userId === participant.userId)?.user.displayName ?? 'ユーザー';
          return (
            <li
              key={participant.participantId}
              title={`${displayName}${participant.muted ? '（ミュート中）' : participant.speaking ? '（発言中）' : ''}`}
              className={`max-w-full truncate rounded-full border px-2 py-0.5 text-[11px] ${participant.speaking ? 'border-discord-green text-white' : 'border-discord-hover text-discord-muted'}`}
            >
              {participant.muted ? '🔇' : participant.speaking ? '●' : '○'} {displayName}
            </li>
          );
        })}
      </ul>

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
          className={`mt-2 w-full rounded px-2 py-2 text-xs font-semibold disabled:opacity-40 ${pushToTalkActive ? 'bg-discord-green text-white' : 'bg-discord-input text-discord-text'}`}
        >
          {muted ? 'ミュートを解除してください' : pushToTalkActive ? '送信中 — 離すと停止' : '押している間だけ話す'}
        </button>
      )}

      <details className="mt-2 text-xs text-discord-muted">
        <summary className="cursor-pointer rounded px-1 py-1 hover:bg-discord-hover hover:text-white">音声設定</summary>
        <div className="mt-2 space-y-2">
          <label className="block">
            話し方
            <select value={mode} onChange={(event) => setMode(event.target.value === 'push-to-talk' ? 'push-to-talk' : 'voice-activity')} className="mt-1 w-full rounded bg-discord-input px-2 py-1.5 text-discord-text">
              <option value="voice-activity">音声検出</option>
              <option value="push-to-talk">プッシュトゥトーク</option>
            </select>
          </label>
          <label className="block">
            マイク
            <select value={selectedInputId} onChange={(event) => void setInputDevice(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-2 py-1.5 text-discord-text">
              <option value="">システム既定</option>
              {inputDevices.filter((device) => device.deviceId !== 'default').map((device) => (
                <option key={device.deviceId} value={device.deviceId}>{device.label}</option>
              ))}
            </select>
          </label>
          {supportsAudioOutputSelection() && (
            <label className="block">
              スピーカー
              <select value={selectedOutputId} onChange={(event) => setOutputDevice(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-2 py-1.5 text-discord-text">
                <option value="">システム既定</option>
                {outputDevices.filter((device) => device.deviceId !== 'default').map((device) => (
                  <option key={device.deviceId} value={device.deviceId}>{device.label}</option>
                ))}
              </select>
            </label>
          )}
        </div>
      </details>

      {error && <p role="alert" className="mt-2 text-xs text-discord-red">通話に問題が発生しました。接続を確認してください。</p>}
      {participants.map((participant) => participant.participantId === self?.participantId ? null : (
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
    return () => { audio.srcObject = null; };
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
