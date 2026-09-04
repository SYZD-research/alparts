import { useEffect, useState } from 'react';
import {
  Permissions,
  type Channel,
  type ChannelReadState,
  type NotificationLevel,
  type VoiceParticipant,
  type WorkspaceMember,
} from '@alparts/shared';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useChannelStore } from '../../stores/channel.store';
import { useAuthStore } from '../../stores/auth.store';
import { useDmStore } from '../../stores/dm.store';
import { directMessageTitle } from '../../stores/dm-model';
import { useUiStore } from '../../stores/ui.store';
import { hasCombinedPermission } from '../../stores/permission-model';
import type { DirectMessageConversation } from '../../services/api';
import { useUserStateStore } from '../../stores/user-state.store';
import { defaultChannelReadState, scanLoadedMentionUnread } from '../../stores/user-state-model';
import { useMessageStore } from '../../stores/message.store';
import { useVoiceStore } from '../../stores/voice.store';
import { VoiceCallPanel } from '../voice/VoiceCallPanel';

const EMPTY_DMS: DirectMessageConversation[] = [];
const EMPTY_CHANNEL_STATES: Record<string, ChannelReadState> = {};

export function ChannelSidebar() {
  const { activeWorkspaceId, categories, members } = useWorkspaceStore();
  const { channels, activeChannelId, setActiveChannel } = useChannelStore();
  const { user } = useAuthStore();
  const conversations = useDmStore((state) => activeWorkspaceId
    ? state.conversationsByWorkspace[activeWorkspaceId] || EMPTY_DMS
    : EMPTY_DMS);
  const dmError = useDmStore((state) => activeWorkspaceId ? state.errorsByWorkspace[activeWorkspaceId] : null);
  const isLoadingDms = useDmStore((state) => Boolean(activeWorkspaceId && state.loadingByWorkspace[activeWorkspaceId]));
  const openDmComposer = useUiStore((state) => state.openDmComposer);
  const openChannelManager = useUiStore((state) => state.openChannelManager);
  const openWorkspaceManager = useUiStore((state) => state.openWorkspaceManager);
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(new Set());
  const [expandedPreferenceKey, setExpandedPreferenceKey] = useState<string | null>(null);
  const currentMember = useWorkspaceStore((state) => state.members.find((member) => member.userId === user?.id));
  const channelStates = useUserStateStore((state) => activeWorkspaceId
    ? state.channelStatesByWorkspace[activeWorkspaceId] || EMPTY_CHANNEL_STATES
    : EMPTY_CHANNEL_STATES);
  const showHidden = useUserStateStore((state) => Boolean(activeWorkspaceId && state.showHiddenByWorkspace[activeWorkspaceId]));
  const channelStateError = useUserStateStore((state) => activeWorkspaceId ? state.errorsByWorkspace[activeWorkspaceId] : null);
  const preferenceSaving = useUserStateStore((state) => state.preferenceSavingByChannel);
  const preferenceErrors = useUserStateStore((state) => state.preferenceErrorsByChannel);
  const updatePreference = useUserStateStore((state) => state.updatePreference);
  const toggleShowHidden = useUserStateStore((state) => state.toggleShowHidden);
  const messagesByChannel = useMessageStore((state) => state.messagesByChannel);
  const hasMoreByChannel = useMessageStore((state) => state.hasMore);
  const voiceStatus = useVoiceStore((state) => state.status);
  const voiceChannelId = useVoiceStore((state) => state.channelId);
  const voiceParticipantsByChannel = useVoiceStore((state) => state.participantsByChannel);
  const joinVoice = useVoiceStore((state) => state.join);
  const canManageChannels = hasCombinedPermission(
    currentMember?.roles.map((role) => role.permissions) || [],
    Permissions.MANAGE_CHANNELS,
  );

  useEffect(() => {
    if (!activeChannelId || showHidden || !channelStates[activeChannelId]?.hidden) return;
    const nextVisible = channels.find((channel) => (
      channel.type !== 'voice' && !channelStates[channel.id]?.hidden
    ));
    if (nextVisible) setActiveChannel(nextVisible.id);
  }, [activeChannelId, channelStates, channels, setActiveChannel, showHidden]);

  if (!activeWorkspaceId) return null;

  const toggleCategory = (id: string) => {
    setCollapsedCategories((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const stateFor = (channelId: string) => channelStates[channelId] || defaultChannelReadState(channelId);
  const isVisible = (channel: Channel) => !stateFor(channel.id).hidden || showHidden;
  const visibleChannels = channels.filter((channel) => (
    channel.type !== 'dm' && isVisible(channel)
  ));
  const favoriteChannels = channels.filter((channel) => stateFor(channel.id).favorite && isVisible(channel));
  const hiddenCount = channels.filter((channel) => stateFor(channel.id).hidden).length;
  const conversationByChannel = new Map(conversations.map((conversation) => [conversation.channelId, conversation]));

  const labelFor = (channel: Channel) => {
    const conversation = conversationByChannel.get(channel.id);
    return conversation && user ? directMessageTitle(conversation, user.id) : channel.name;
  };

  const channelRow = (channel: Channel, instance: string) => {
    const preference = stateFor(channel.id);
    const mentionScan = user && channel.type !== 'voice'
      ? scanLoadedMentionUnread(
        messagesByChannel[channel.id] || [],
        user,
        preference.lastReadMessageId,
        Boolean(hasMoreByChannel[channel.id]),
      )
      : null;
    return (
      <ChannelRow
        key={`${instance}:${channel.id}`}
        channel={channel}
        label={labelFor(channel)}
        preference={preference}
        mentionCount={mentionScan?.completeForUnreadWindow ? mentionScan.count : 0}
        active={activeChannelId === channel.id}
        expanded={expandedPreferenceKey === `${instance}:${channel.id}`}
        saving={Boolean(preferenceSaving[channel.id])}
        error={preferenceErrors[channel.id]}
        participants={voiceParticipantsByChannel[channel.id] || []}
        members={members}
        voiceActive={channel.type === 'voice' && voiceChannelId === channel.id && (voiceStatus === 'connected' || voiceStatus === 'joining')}
        onSelect={() => {
          if (channel.type === 'voice') void joinVoice(channel.id);
          else setActiveChannel(channel.id);
        }}
        onToggleSettings={() => setExpandedPreferenceKey((current) => current === `${instance}:${channel.id}` ? null : `${instance}:${channel.id}`)}
        onUpdate={(updates) => updatePreference(activeWorkspaceId, channel.id, updates)}
      />
    );
  };

  return (
    <div className="flex h-full w-full flex-col bg-discord-sidebar">
      <div className="flex h-12 items-center justify-between gap-2 border-b border-discord-bg px-4 shadow-sm">
        <h2 className="truncate font-bold text-white">
          {useWorkspaceStore.getState().workspaces.find((workspace) => workspace.id === activeWorkspaceId)?.name || 'ワークスペース'}
        </h2>
        <div className="flex shrink-0 items-center">
          <button type="button" onClick={openWorkspaceManager} className="rounded px-2 py-1 text-discord-muted hover:bg-discord-hover hover:text-white" title="招待・ロール・権限を管理" aria-label="ワークスペースの招待・ロール・権限を管理">◈</button>
          {canManageChannels && <button type="button" onClick={openChannelManager} className="rounded px-2 py-1 text-discord-muted hover:bg-discord-hover hover:text-white" title="チャンネルとカテゴリーを管理" aria-label="チャンネルとカテゴリーを管理">⚙</button>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pt-3">
        {channelStateError && <p role="alert" className="mb-2 rounded bg-discord-red/10 px-2 py-1 text-xs text-discord-red">チャンネルを読み込めませんでした</p>}

        {favoriteChannels.length > 0 && (
          <section className="mb-4" aria-labelledby="favorite-channels-title">
            <h3 id="favorite-channels-title" className="px-1 py-1 text-xs font-bold uppercase tracking-wide text-discord-muted">★ お気に入り</h3>
            {favoriteChannels.map((channel) => channelRow(channel, 'favorite'))}
          </section>
        )}

        <section className="mb-4" aria-labelledby="direct-messages-title">
          <div className="flex items-center justify-between px-1 py-1 text-xs font-bold uppercase tracking-wide text-discord-muted">
            <h3 id="direct-messages-title">ダイレクトメッセージ</h3>
            <button type="button" onClick={() => openDmComposer(activeWorkspaceId)} className="rounded px-1 text-base font-normal hover:bg-discord-hover hover:text-white" aria-label="DMを開始">+</button>
          </div>
          {dmError && <p role="alert" className="px-2 py-1 text-xs text-discord-red">DMを読み込めませんでした</p>}
          {isLoadingDms && <p role="status" className="px-2 py-1 text-xs text-discord-muted">DMを読み込み中…</p>}
          {!isLoadingDms && !dmError && conversations.length === 0 && <p className="px-2 py-1 text-xs text-discord-muted">まだDMはありません</p>}
          {conversations.map((conversation) => {
            const channel = channels.find((candidate) => candidate.id === conversation.channelId);
            if (!channel || !isVisible(channel)) return null;
            return channelRow(channel, 'dm');
          })}
        </section>

        {categories.map((category) => {
          const categoryChannels = visibleChannels.filter((channel) => channel.categoryId === category.id);
          if (categoryChannels.length === 0) return null;
          const collapsed = collapsedCategories.has(category.id);
          return (
            <section key={category.id} className="mb-1">
              <button type="button" onClick={() => toggleCategory(category.id)} aria-expanded={!collapsed} className="flex w-full items-center px-1 py-1 text-xs font-bold uppercase tracking-wide text-discord-muted hover:text-discord-text">
                <svg width="12" height="12" viewBox="0 0 12 12" className={`mr-0.5 transition-transform ${collapsed ? '-rotate-90' : ''}`} fill="currentColor" aria-hidden="true"><path d="M2 4l4 4 4-4" /></svg>
                {category.name}
              </button>
              {!collapsed && <div className="ml-2">{categoryChannels.map((channel) => channelRow(channel, `category-${category.id}`))}</div>}
            </section>
          );
        })}

        {visibleChannels.some((channel) => !channel.categoryId) && (
          <section className="mb-1" aria-labelledby="uncategorized-channels-title">
            <h3 id="uncategorized-channels-title" className="px-1 py-1 text-xs font-bold uppercase tracking-wide text-discord-muted">チャンネル</h3>
            {visibleChannels.filter((channel) => !channel.categoryId).map((channel) => channelRow(channel, 'uncategorized'))}
          </section>
        )}

        {hiddenCount > 0 && (
          <button type="button" onClick={() => toggleShowHidden(activeWorkspaceId)} aria-pressed={showHidden} className="mt-2 flex w-full items-center rounded px-2 py-1.5 text-xs text-discord-muted hover:bg-discord-hover hover:text-white">
            {showHidden ? '非表示チャンネルを隠す' : `非表示チャンネルを表示（${hiddenCount}）`}
          </button>
        )}
        <p className="mt-2 px-2 text-[10px] leading-4 text-discord-muted">テキストチャンネルでは、ミュートすると通知を止められます。非表示にすると一覧から隠れます。</p>

        {canManageChannels && (
          <button type="button" onClick={openChannelManager} className="mt-2 flex w-full items-center rounded px-2 py-1.5 text-sm text-discord-muted hover:bg-discord-hover hover:text-discord-text"><span className="mr-1.5">+</span>チャンネルを追加・管理</button>
        )}
      </div>

      <VoiceCallPanel />

      {user && (
        <div className="flex h-14 items-center bg-discord-bg/50 px-2">
          <div className="flex min-w-0 flex-1 items-center gap-2 rounded px-2 py-1">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-discord-accent text-sm font-bold text-white">{user.displayName.slice(0, 1).toUpperCase()}</div>
            <div className="min-w-0"><div className="truncate text-sm font-medium text-white">{user.displayName}</div><div className="truncate text-xs text-discord-muted">オンライン</div></div>
          </div>
        </div>
      )}
    </div>
  );
}

function ChannelRow({
  channel,
  label,
  preference,
  mentionCount,
  active,
  expanded,
  saving,
  error,
  participants,
  members,
  voiceActive,
  onSelect,
  onToggleSettings,
  onUpdate,
}: {
  channel: Channel;
  label: string;
  preference: ChannelReadState;
  mentionCount: number;
  active: boolean;
  expanded: boolean;
  saving: boolean;
  error: string | null | undefined;
  participants: VoiceParticipant[];
  members: WorkspaceMember[];
  voiceActive: boolean;
  onSelect: () => void;
  onToggleSettings: () => void;
  onUpdate: (updates: { favorite?: boolean; muted?: boolean; hidden?: boolean; notificationLevel?: NotificationLevel }) => Promise<void>;
}) {
  const isVoice = channel.type === 'voice';
  const prefix = channel.type === 'dm' ? '@' : channel.type === 'announcement' ? '!' : isVoice ? '🔊' : '#';
  const unreadLabel = preference.unreadCount > 99 ? '99+' : String(preference.unreadCount);
  const participantUsers = [...new Set(participants.map((participant) => participant.userId))]
    .map((userId) => ({
      member: members.find((candidate) => candidate.userId === userId),
      speaking: participants.some((participant) => participant.userId === userId && participant.speaking),
      muted: participants.filter((participant) => participant.userId === userId).every((participant) => participant.muted),
    }));
  return (
    <div className={`mb-0.5 rounded ${preference.hidden ? 'opacity-65' : ''}`}>
      <div className="flex items-center gap-0.5">
        <button type="button" onClick={onSelect} className={`flex min-w-0 flex-1 items-center rounded px-2 py-1.5 text-sm transition-colors ${(isVoice ? voiceActive : active) ? 'bg-discord-active text-white' : 'text-discord-channel hover:bg-discord-hover hover:text-discord-text'}`}>
          <span className="mr-1.5 text-discord-muted" aria-hidden="true">{prefix}</span>
          <span className="truncate">{label}</span>
          <span className="ml-auto flex shrink-0 items-center gap-1 pl-1">
            {!isVoice && preference.muted && <span title="ミュート中" aria-label="ミュート中">🔕</span>}
            {!isVoice && mentionCount > 0 && <span title={`メンション${mentionCount}件`} className="rounded bg-discord-red px-1 text-[10px] text-white">@{mentionCount}</span>}
            {!isVoice && preference.unreadCount > 0 && <span aria-label={`未読${preference.unreadCount}件`} className="min-w-5 rounded-full bg-discord-accent px-1 text-center text-[10px] text-white">{unreadLabel}</span>}
          </span>
        </button>
        <button type="button" onClick={onToggleSettings} aria-expanded={expanded} aria-label={`${label}の${isVoice ? '表示設定' : '通知と表示設定'}`} className="rounded px-1.5 py-1 text-xs text-discord-muted hover:bg-discord-hover hover:text-white">⋯</button>
      </div>
      {isVoice && participantUsers.length > 0 && (
        <ul aria-label={`${label}の参加者`} className="ml-7 flex flex-wrap gap-1 px-1 pb-1.5 pt-1">
          {participantUsers.map(({ member, speaking, muted }, index) => {
            const displayName = member?.user.displayName || 'ユーザー';
            return (
              <li
                key={member?.userId || `${displayName}:${index}`}
                title={`${displayName}${muted ? '（ミュート中）' : speaking ? '（発言中）' : ''}`}
                aria-label={`${displayName}${muted ? '、ミュート中' : speaking ? '、発言中' : ''}`}
                className={`flex h-7 w-7 items-center justify-center rounded-full bg-discord-accent text-[11px] font-bold text-white ${speaking ? 'ring-2 ring-discord-green' : ''} ${muted ? 'opacity-55' : ''}`}
              >
                {displayName.slice(0, 1).toUpperCase()}
              </li>
            );
          })}
        </ul>
      )}
      {expanded && (
        <div role="group" aria-label={`${label}の個人設定`} className="mx-1 mb-1 space-y-2 rounded bg-discord-bg/70 p-2">
          <div className="flex flex-wrap gap-1">
            <button type="button" aria-pressed={preference.favorite} disabled={saving} onClick={() => void onUpdate({ favorite: !preference.favorite }).catch(() => undefined)} className="rounded px-2 py-1 text-xs text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">{preference.favorite ? '★ お気に入り' : '☆ お気に入り'}</button>
            {!isVoice && <button type="button" aria-pressed={preference.muted} disabled={saving} onClick={() => void onUpdate({ muted: !preference.muted }).catch(() => undefined)} className="rounded px-2 py-1 text-xs text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">{preference.muted ? '🔔 ミュート解除' : '🔕 ミュート'}</button>}
            <button type="button" aria-pressed={preference.hidden} disabled={saving} onClick={() => void onUpdate({ hidden: !preference.hidden }).catch(() => undefined)} className="rounded px-2 py-1 text-xs text-discord-muted hover:bg-discord-hover hover:text-white disabled:opacity-50">{preference.hidden ? '表示に戻す' : '非表示'}</button>
          </div>
          {!isVoice && <label className="block text-[11px] text-discord-muted">
            通知レベル
            <select value={preference.notificationLevel} disabled={saving} onChange={(event) => void onUpdate({ notificationLevel: event.target.value as NotificationLevel }).catch(() => undefined)} className="mt-1 w-full rounded bg-discord-input px-2 py-1 text-xs text-discord-text disabled:opacity-50">
              <option value="all">すべて</option>
              <option value="mentions">メンションのみ</option>
              <option value="none">通知なし</option>
            </select>
          </label>}
          {saving && <p role="status" className="text-[10px] text-discord-muted">保存中…</p>}
          {error && <p role="alert" className="text-[10px] text-discord-red">設定を保存できませんでした</p>}
        </div>
      )}
    </div>
  );
}
