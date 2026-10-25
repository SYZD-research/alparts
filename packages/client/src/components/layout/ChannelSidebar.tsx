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
import { Icon, type IconName } from '../ui/Icon';
import { UserAvatar, avatarTone } from '../user/UserAvatar';
import { useT } from '../../i18n';

const EMPTY_DMS: DirectMessageConversation[] = [];
const EMPTY_CHANNEL_STATES: Record<string, ChannelReadState> = {};
const HEADER_TOOL = 'flex h-8 w-8 items-center justify-center rounded-lg text-muted transition-colors hover:bg-hover hover:text-ink-strong';
const SECTION_TITLE = 'px-2 pb-1 pt-0.5 text-xs font-medium text-muted';
const CHANNEL_ICONS: Record<Channel['type'], IconName> = {
  text: 'hash',
  dm: 'at',
  announcement: 'announcement',
  voice: 'voice',
  forum: 'forum',
};
const PREFERENCE_CHIP = 'rounded-lg border border-line px-2.5 py-1 text-xs text-ink-soft transition-colors hover:bg-hover hover:text-ink-strong aria-pressed:border-transparent aria-pressed:bg-selected aria-pressed:text-ink-strong disabled:opacity-50';

export function ChannelSidebar({ onNavigateToChat }: { onNavigateToChat?: () => void }) {
  const t = useT();
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
          else {
            setActiveChannel(channel.id);
            onNavigateToChat?.();
          }
        }}
        onToggleSettings={() => setExpandedPreferenceKey((current) => current === `${instance}:${channel.id}` ? null : `${instance}:${channel.id}`)}
        onUpdate={(updates) => updatePreference(activeWorkspaceId, channel.id, updates)}
      />
    );
  };

  return (
    <div className="flex h-full min-h-0 w-full flex-col bg-panel">
      <div className="flex h-12 shrink-0 items-center justify-between gap-2 border-b border-line pl-4 pr-2">
        <h2 className="truncate text-[15px] font-semibold text-ink-strong">
          {useWorkspaceStore.getState().workspaces.find((workspace) => workspace.id === activeWorkspaceId)?.name || t('ワークスペース')}
        </h2>
        <div className="flex shrink-0 items-center gap-0.5">
          <button type="button" onClick={openWorkspaceManager} className={HEADER_TOOL} title={t('招待・ロール・権限を管理')} aria-label={t('ワークスペースの招待・ロール・権限を管理')}><Icon name="sliders" /></button>
          {canManageChannels && <button type="button" onClick={openChannelManager} className={HEADER_TOOL} title={t('チャンネルとカテゴリーを管理')} aria-label={t('チャンネルとカテゴリーを管理')}><Icon name="settings" /></button>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-3 pt-3">
        {channelStateError && <p role="alert" className="mb-2 rounded-lg bg-danger/10 px-2.5 py-1.5 text-xs text-danger">{t('チャンネルを読み込めませんでした')}</p>}

        {favoriteChannels.length > 0 && (
          <section className="mb-4" aria-labelledby="favorite-channels-title">
            <h3 id="favorite-channels-title" className={SECTION_TITLE}>{t('★ お気に入り')}</h3>
            {favoriteChannels.map((channel) => channelRow(channel, 'favorite'))}
          </section>
        )}

        <section className="mb-4" aria-labelledby="direct-messages-title">
          <div className="flex items-center justify-between pr-1">
            <h3 id="direct-messages-title" className={SECTION_TITLE}>{t('ダイレクトメッセージ')}</h3>
            <button type="button" onClick={() => openDmComposer(activeWorkspaceId)} className="flex h-6 w-6 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-ink-strong" aria-label={t('DMを開始')}><Icon name="plus" size={16} /></button>
          </div>
          {dmError && <p role="alert" className="px-2 py-1 text-xs text-danger">{t('DMを読み込めませんでした')}</p>}
          {isLoadingDms && <p role="status" className="px-2 py-1 text-xs text-muted">{t('DMを読み込み中…')}</p>}
          {!isLoadingDms && !dmError && conversations.length === 0 && <p className="px-2 py-1 text-xs text-muted">{t('まだDMはありません')}</p>}
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
            <section key={category.id} className="mb-3">
              <button type="button" onClick={() => toggleCategory(category.id)} aria-expanded={!collapsed} className={`${SECTION_TITLE} flex w-full items-center gap-1 rounded-md hover:text-ink`}>
                <Icon name="chevronDown" size={14} className={`transition-transform ${collapsed ? '-rotate-90' : ''}`} />
                {category.name}
              </button>
              {!collapsed && <div>{categoryChannels.map((channel) => channelRow(channel, `category-${category.id}`))}</div>}
            </section>
          );
        })}

        {visibleChannels.some((channel) => !channel.categoryId) && (
          <section className="mb-3" aria-labelledby="uncategorized-channels-title">
            <h3 id="uncategorized-channels-title" className={SECTION_TITLE}>{t('チャンネル')}</h3>
            {visibleChannels.filter((channel) => !channel.categoryId).map((channel) => channelRow(channel, 'uncategorized'))}
          </section>
        )}

        {hiddenCount > 0 && (
          <button type="button" onClick={() => toggleShowHidden(activeWorkspaceId)} aria-pressed={showHidden} className="mt-1 flex w-full items-center rounded-lg px-2 py-1.5 text-xs text-muted hover:bg-hover hover:text-ink-strong">
            {showHidden ? t('非表示チャンネルを隠す') : t('非表示チャンネルを表示（{count}）', { count: hiddenCount })}
          </button>
        )}
        <p className="mt-2 px-2 text-[11px] leading-relaxed text-muted">{t('テキストチャンネルでは、ミュートすると通知を止められます。非表示にすると一覧から隠れます。')}</p>

        {canManageChannels && (
          <button type="button" onClick={openChannelManager} className="mt-2 flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-muted hover:bg-hover hover:text-ink"><Icon name="plus" size={16} />{t('チャンネルを追加・管理')}</button>
        )}
      </div>

      <VoiceCallPanel />

      {user && (
        <div className="flex h-14 shrink-0 items-center gap-2.5 border-t border-line px-3">
          <div className="relative">
            <UserAvatar displayName={user.displayName} avatarUrl={user.avatarUrl} size="sm" />
            <span aria-hidden="true" className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-success ring-2 ring-panel" />
          </div>
          <div className="min-w-0"><div className="truncate text-sm font-medium text-ink-strong">{user.displayName}</div><div className="truncate text-xs text-muted">{t('オンライン')}</div></div>
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
  const t = useT();
  const isVoice = channel.type === 'voice';
  const selected = isVoice ? voiceActive : active;
  const unreadLabel = preference.unreadCount > 99 ? '99+' : String(preference.unreadCount);
  const participantUsers = [...new Set(participants.map((participant) => participant.userId))]
    .map((userId) => ({
      member: members.find((candidate) => candidate.userId === userId),
      speaking: participants.some((participant) => participant.userId === userId && participant.speaking),
      muted: participants.filter((participant) => participant.userId === userId).every((participant) => participant.muted),
    }));
  return (
    <div className={`mb-px rounded-lg ${preference.hidden ? 'opacity-65' : ''}`}>
      <div className="flex items-center gap-0.5">
        <button type="button" onClick={onSelect} className={`flex min-w-0 flex-1 items-center gap-2 rounded-lg px-2 py-1.5 text-sm transition-colors ${selected ? 'bg-selected font-medium text-ink-strong' : 'text-ink-soft hover:bg-hover hover:text-ink'}`}>
          <Icon name={CHANNEL_ICONS[channel.type]} size={16} className={selected ? 'text-ink' : 'text-muted'} />
          <span className="truncate">{label}</span>
          <span className="ml-auto flex shrink-0 items-center gap-1 pl-1">
            {!isVoice && preference.muted && <span role="img" title={t('ミュート中')} aria-label={t('ミュート中')} className="text-muted"><Icon name="bellOff" size={14} /></span>}
            {!isVoice && mentionCount > 0 && <span title={t('メンション{count}件', { count: mentionCount })} className="rounded-full bg-danger px-1.5 text-[10px] font-semibold leading-4 text-white">@{mentionCount}</span>}
            {!isVoice && preference.unreadCount > 0 && <span aria-label={t('未読{count}件', { count: preference.unreadCount })} className="min-w-5 rounded-full bg-accent px-1.5 text-center text-[10px] font-semibold leading-4 text-on-accent">{unreadLabel}</span>}
          </span>
        </button>
        <button type="button" onClick={onToggleSettings} aria-expanded={expanded} aria-label={isVoice ? t('{name}の表示設定', { name: label }) : t('{name}の通知と表示設定', { name: label })} className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition-colors hover:bg-hover hover:text-ink-strong ${expanded ? 'bg-hover text-ink-strong' : 'text-muted'}`}><Icon name="more" size={16} /></button>
      </div>
      {isVoice && participantUsers.length > 0 && (
        <ul aria-label={t('{name}の参加者', { name: label })} className="ml-8 flex flex-wrap gap-1.5 px-1 pb-1.5 pt-1">
          {participantUsers.map(({ member, speaking, muted }, index) => {
            const displayName = member?.user.displayName || t('ユーザー');
            return (
              <li
                key={member?.userId || `${displayName}:${index}`}
                title={muted ? t('{name}（ミュート中）', { name: displayName }) : speaking ? t('{name}（発言中）', { name: displayName }) : displayName}
                aria-label={muted ? t('{name}、ミュート中', { name: displayName }) : speaking ? t('{name}、発言中', { name: displayName }) : displayName}
                className={`flex h-6 w-6 items-center justify-center rounded-full ${avatarTone(displayName)} text-[10px] font-semibold text-white ${speaking ? 'ring-2 ring-success ring-offset-2 ring-offset-panel' : ''} ${muted ? 'opacity-55' : ''}`}
              >
                {displayName.slice(0, 1).toUpperCase()}
              </li>
            );
          })}
        </ul>
      )}
      {expanded && (
        <div role="group" aria-label={t('{name}の個人設定', { name: label })} className="mx-1 mb-2 mt-1 space-y-2.5 rounded-xl border border-line bg-canvas p-2.5">
          <div className="flex flex-wrap gap-1.5">
            <button type="button" aria-pressed={preference.favorite} disabled={saving} onClick={() => void onUpdate({ favorite: !preference.favorite }).catch(() => undefined)} className={PREFERENCE_CHIP}>{preference.favorite ? t('★ お気に入り') : t('☆ お気に入り')}</button>
            {!isVoice && <button type="button" aria-pressed={preference.muted} disabled={saving} onClick={() => void onUpdate({ muted: !preference.muted }).catch(() => undefined)} className={PREFERENCE_CHIP}>{preference.muted ? t('🔔 ミュート解除') : t('🔕 ミュート')}</button>}
            <button type="button" aria-pressed={preference.hidden} disabled={saving} onClick={() => void onUpdate({ hidden: !preference.hidden }).catch(() => undefined)} className={PREFERENCE_CHIP}>{preference.hidden ? t('表示に戻す') : t('非表示')}</button>
          </div>
          {!isVoice && <label className="block text-[11px] text-muted">
            {t('通知レベル')}
            <select value={preference.notificationLevel} disabled={saving} onChange={(event) => void onUpdate({ notificationLevel: event.target.value as NotificationLevel }).catch(() => undefined)} className="mt-1 w-full rounded-lg border border-line bg-field px-2 py-1.5 text-xs text-ink disabled:opacity-50">
              <option value="all">{t('すべて|notification-level')}</option>
              <option value="mentions">{t('メンションのみ')}</option>
              <option value="none">{t('通知なし|notification-level')}</option>
            </select>
          </label>}
          {saving && <p role="status" className="text-[10px] text-muted">{t('保存中…')}</p>}
          {error && <p role="alert" className="text-[10px] text-danger">{t('設定を保存できませんでした')}</p>}
        </div>
      )}
    </div>
  );
}
