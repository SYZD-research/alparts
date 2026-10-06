import { useEffect, useMemo, useState } from 'react';
import { Permissions, type Channel } from '@alparts/shared';
import { ApiError, api, type ChannelMemberSummary } from '../../services/api';
import { useAuthStore } from '../../stores/auth.store';
import { useChannelStore } from '../../stores/channel.store';
import { hasCombinedPermission } from '../../stores/permission-model';
import { useUiStore } from '../../stores/ui.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { Dialog } from '../ui/Dialog';
import { PermissionOverrideManager } from './PermissionOverrideManager';
import { t, useT } from '../../i18n';

type ManagerTab = 'create' | 'edit' | 'categories' | 'permissions';
type Confirmation =
  | { kind: 'delete-channel'; id: string; label: string }
  | { kind: 'delete-category'; id: string; label: string }
  | { kind: 'remove-member'; channelId: string; userId: string; label: string; self: boolean };

interface ChannelFormState {
  name: string;
  topic: string;
  categoryId: string;
  type: 'text' | 'announcement' | 'voice' | 'forum';
  isPrivate: boolean;
  position: string;
}

const EMPTY_CHANNEL_FORM: ChannelFormState = {
  name: '',
  topic: '',
  categoryId: '',
  type: 'text',
  isPrivate: false,
  position: '0',
};

function mutationError(error: unknown): string {
  if (error instanceof ApiError && error.code === 'MEMBER_HIERARCHY') {
    return t('自分と同じか上の順位のメンバーは、非公開チャンネルから削除できません。');
  }
  if (error instanceof ApiError && error.status === 403) return t('チャンネル管理権限がありません。状態は変更されていません。');
  if (error instanceof Error && error.message === t('位置は0〜1000000の整数で入力してください')) return error.message;
  return t('変更を保存できませんでした。もう一度お試しください。');
}

function parsePosition(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 1_000_000) throw new Error(t('位置は0〜1000000の整数で入力してください'));
  return parsed;
}

function channelForm(channel: Channel): ChannelFormState {
  return {
    name: channel.name,
    topic: channel.topic || '',
    categoryId: channel.categoryId || '',
    type: channel.type === 'announcement' || channel.type === 'voice' || channel.type === 'forum' ? channel.type : 'text',
    isPrivate: channel.isPrivate,
    position: String(channel.position),
  };
}

export function ChannelManagerDialog() {
  const t = useT();
  const open = useUiStore((state) => state.isChannelManagerOpen);
  const close = useUiStore((state) => state.closeChannelManager);
  const authorizationRefreshVersion = useUiStore((state) => state.authorizationRefreshVersion);
  const workspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const categories = useWorkspaceStore((state) => state.categories);
  const workspaceMembers = useWorkspaceStore((state) => state.members);
  const loadCategories = useWorkspaceStore((state) => state.loadCategories);
  const channels = useChannelStore((state) => state.channels);
  const activeChannelId = useChannelStore((state) => state.activeChannelId);
  const setActiveChannel = useChannelStore((state) => state.setActiveChannel);
  const loadChannels = useChannelStore((state) => state.loadChannels);
  const currentUser = useAuthStore((state) => state.user);
  const currentMember = workspaceMembers.find((member) => member.userId === currentUser?.id);
  const canManage = hasCombinedPermission(
    currentMember?.roles.map((role) => role.permissions) || [],
    Permissions.MANAGE_CHANNELS,
  );
  const manageableChannels = useMemo(
    () => channels.filter((channel) => channel.type !== 'dm'),
    [channels],
  );
  const [tab, setTab] = useState<ManagerTab>('create');
  const [selectedChannelId, setSelectedChannelId] = useState('');
  const [form, setForm] = useState<ChannelFormState>(EMPTY_CHANNEL_FORM);
  const [selectedCategoryId, setSelectedCategoryId] = useState('');
  const [categoryName, setCategoryName] = useState('');
  const [categoryPosition, setCategoryPosition] = useState('0');
  const [channelMembers, setChannelMembers] = useState<ChannelMemberSummary[]>([]);
  const [memberToAdd, setMemberToAdd] = useState('');
  const [isLoadingMembers, setIsLoadingMembers] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);

  const selectedChannel = manageableChannels.find((channel) => channel.id === selectedChannelId) || null;
  const selectedCategory = categories.find((category) => category.id === selectedCategoryId) || null;

  useEffect(() => {
    if (!open) return;
    const initial = manageableChannels.find((channel) => channel.id === activeChannelId) || manageableChannels[0] || null;
    setSelectedChannelId(initial?.id || '');
    setForm(initial ? channelForm(initial) : EMPTY_CHANNEL_FORM);
    setSelectedCategoryId('');
    setCategoryName('');
    setCategoryPosition('0');
    setTab(manageableChannels.length > 0 ? 'edit' : 'create');
    setError(null);
    setNotice(null);
    setConfirmation(null);
  }, [open, workspaceId]);

  useEffect(() => {
    if (tab !== 'edit') return;
    const channel = manageableChannels.find((candidate) => candidate.id === selectedChannelId);
    if (channel) setForm(channelForm(channel));
  }, [manageableChannels, selectedChannelId, tab]);

  useEffect(() => {
    if (!selectedCategory) return;
    setCategoryName(selectedCategory.name);
    setCategoryPosition(String(selectedCategory.position));
  }, [selectedCategory]);

  const loadPrivateMembers = async (channel: Channel | null) => {
    if (!channel?.isPrivate) {
      setChannelMembers([]);
      return;
    }
    setIsLoadingMembers(true);
    try {
      setChannelMembers(await api.getChannelMembers(channel.id));
    } catch (caught) {
      setError(mutationError(caught));
      setChannelMembers([]);
    } finally {
      setIsLoadingMembers(false);
    }
  };

  useEffect(() => {
    if (open && tab === 'edit') void loadPrivateMembers(selectedChannel);
  }, [open, selectedChannel?.id, selectedChannel?.isPrivate, tab]);

  const refreshWorkspace = async () => {
    if (!workspaceId) return [] as Channel[];
    const [nextChannels] = await Promise.all([
      loadChannels(workspaceId),
      loadCategories(workspaceId),
    ]);
    return nextChannels;
  };

  const prepareMutation = () => {
    setBusy(true);
    setError(null);
    setNotice(null);
  };

  const submitCreateChannel = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!workspaceId || busy) return;
    prepareMutation();
    try {
      const created = await api.createChannel(workspaceId, form.name.trim(), {
        ...(form.categoryId ? { categoryId: form.categoryId } : {}),
        type: form.type,
        isPrivate: form.isPrivate,
        topic: form.topic.trim(),
        position: parsePosition(form.position),
      });
      await refreshWorkspace();
      if (created.type !== 'voice') setActiveChannel(created.id);
      setSelectedChannelId(created.id);
      setTab('edit');
      setNotice(t('「{name}」を作成しました。', { name: created.name }));
    } catch (caught) {
      setError(mutationError(caught));
    } finally {
      setBusy(false);
    }
  };

  const submitUpdateChannel = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedChannel || busy) return;
    prepareMutation();
    try {
      const categoryId = form.categoryId || null;
      // Privacy and category changes ask for identity confirmation, so send
      // them only when they actually change.
      const updated = await api.updateChannel(selectedChannel.id, {
        name: form.name.trim(),
        topic: form.topic.trim(),
        position: parsePosition(form.position),
        ...(form.isPrivate !== selectedChannel.isPrivate ? { isPrivate: form.isPrivate } : {}),
        ...(categoryId !== (selectedChannel.categoryId ?? null) ? { categoryId } : {}),
      });
      await refreshWorkspace();
      setSelectedChannelId(updated.id);
      setNotice(t('「{name}」を更新しました。', { name: updated.name }));
      await loadPrivateMembers(updated);
    } catch (caught) {
      setError(mutationError(caught));
    } finally {
      setBusy(false);
    }
  };

  const submitCategory = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!workspaceId || busy) return;
    prepareMutation();
    try {
      const position = parsePosition(categoryPosition);
      if (selectedCategory) {
        const updated = await api.updateCategory(workspaceId, selectedCategory.id, { name: categoryName.trim(), position });
        setNotice(t('カテゴリー「{name}」を更新しました。', { name: updated.name }));
      } else {
        const created = await api.createCategory(workspaceId, categoryName.trim(), position);
        setSelectedCategoryId(created.id);
        setNotice(t('カテゴリー「{name}」を作成しました。', { name: created.name }));
      }
      await refreshWorkspace();
    } catch (caught) {
      setError(mutationError(caught));
    } finally {
      setBusy(false);
    }
  };

  const addPrivateMember = async () => {
    if (!selectedChannel || !memberToAdd || busy) return;
    prepareMutation();
    try {
      await api.addChannelMember(selectedChannel.id, memberToAdd);
      await loadPrivateMembers(selectedChannel);
      setMemberToAdd('');
      setNotice(t('非公開チャンネルへメンバーを追加しました。'));
    } catch (caught) {
      setError(mutationError(caught));
    } finally {
      setBusy(false);
    }
  };

  const executeConfirmation = async () => {
    if (!confirmation || !workspaceId || busy) return;
    prepareMutation();
    try {
      if (confirmation.kind === 'delete-channel') {
        await api.deleteChannel(confirmation.id);
        const nextChannels = await refreshWorkspace();
        const next = nextChannels?.find((channel) => channel.type !== 'dm' && channel.type !== 'voice') || null;
        if (activeChannelId === confirmation.id) setActiveChannel(next?.id || null);
        setSelectedChannelId(next?.id || '');
        setNotice(t('チャンネルを削除しました。'));
      } else if (confirmation.kind === 'delete-category') {
        await api.deleteCategory(workspaceId, confirmation.id);
        await refreshWorkspace();
        setSelectedCategoryId('');
        setCategoryName('');
        setCategoryPosition('0');
        setNotice(t('カテゴリーを削除し、所属チャンネルをカテゴリーなしへ移動しました。'));
      } else {
        await api.removeChannelMember(confirmation.channelId, confirmation.userId);
        if (confirmation.self) {
          const nextChannels = await refreshWorkspace();
          setActiveChannel(nextChannels?.find((channel) => (
            channel.id !== confirmation.channelId && channel.type !== 'voice'
          ))?.id || null);
          setSelectedChannelId('');
          setNotice(t('自分を非公開チャンネルから削除しました。'));
        } else {
          await loadPrivateMembers(selectedChannel);
          setNotice(t('非公開チャンネルからメンバーを削除しました。'));
        }
      }
      setConfirmation(null);
    } catch (caught) {
      setError(mutationError(caught));
      setConfirmation(null);
    } finally {
      setBusy(false);
    }
  };

  const eligibleMembers = workspaceMembers.filter((member) => (
    !channelMembers.some((channelMember) => channelMember.id === member.userId)
  ));

  return (
    <Dialog
      open={open}
      onClose={() => { if (!busy) close(); }}
      title={t('チャンネルとカテゴリーの管理')}
      description={t('ここでの変更は、権限がない場合は保存されません。')}
      size="lg"
    >
      {!workspaceId || !canManage ? (
        <div role="alert" className="rounded bg-discord-red/15 p-4 text-sm text-discord-red">{t('チャンネル管理権限がありません。')}</div>
      ) : (
        <div className="space-y-5">
          <div role="tablist" aria-label={t('管理対象')} className="flex gap-1 rounded bg-discord-bg p-1">
            {([
              ['create', t('チャンネル作成')],
              ['edit', t('チャンネル編集')],
              ['categories', t('カテゴリー|tab')],
              ['permissions', t('権限設定')],
            ] as Array<[ManagerTab, string]>).map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="tab"
                aria-selected={tab === value}
                onClick={() => { setTab(value); setError(null); setNotice(null); setConfirmation(null); if (value === 'create') setForm(EMPTY_CHANNEL_FORM); }}
                className={`flex-1 rounded px-3 py-2 text-sm ${tab === value ? 'bg-discord-accent text-white' : 'text-discord-muted hover:bg-discord-hover'}`}
              >
                {label}
              </button>
            ))}
          </div>

          {error && <div role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{error}</div>}
          {notice && <div role="status" className="rounded bg-discord-green/15 px-3 py-2 text-sm text-discord-green">{notice}</div>}
          {confirmation && (
            <div role="alertdialog" aria-label={t('削除の確認')} className="rounded border border-discord-red/60 bg-discord-red/10 p-4">
              <p className="text-sm text-discord-text">{confirmation.label}</p>
              {confirmation.kind === 'remove-member' && (
                <p className="mt-2 text-xs text-discord-muted">{t('削除したメンバーは、このチャンネルの履歴にアクセスできなくなります。')}</p>
              )}
              <div className="mt-3 flex justify-end gap-2">
                <button type="button" onClick={() => setConfirmation(null)} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">{t('キャンセル')}</button>
                <button type="button" onClick={() => { void executeConfirmation(); }} className="rounded bg-discord-red px-3 py-2 text-sm text-white">{t('理解して実行')}</button>
              </div>
            </div>
          )}

          {tab === 'create' && (
            <ChannelForm form={form} setForm={setForm} categories={categories} submit={submitCreateChannel} busy={busy} submitLabel={t('チャンネルを作成|button')} />
          )}

          {tab === 'edit' && (
            <div className="space-y-5">
              <label className="block text-sm text-discord-text">
                {t('編集するチャンネル')}
                <select value={selectedChannelId} onChange={(event) => setSelectedChannelId(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
                  {manageableChannels.map((channel) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
                </select>
              </label>
              {selectedChannel ? (
                <>
                  <ChannelForm form={form} setForm={setForm} categories={categories} submit={submitUpdateChannel} busy={busy} submitLabel={t('変更を保存')} isEditing />
                  <section className="rounded bg-discord-bg p-4">
                    <h3 className="font-medium text-white">{t('非公開チャンネルのメンバー')}</h3>
                    {!selectedChannel.isPrivate ? (
                      <p className="mt-2 text-sm text-discord-muted">{t('非公開に変更して保存すると、メンバーを選べるようになります。')}</p>
                    ) : isLoadingMembers ? (
                      <p className="mt-2 text-sm text-discord-muted">{t('読み込み中…')}</p>
                    ) : (
                      <div className="mt-3 space-y-3">
                        <div className="flex gap-2">
                          <select value={memberToAdd} onChange={(event) => setMemberToAdd(event.target.value)} className="min-w-0 flex-1 rounded bg-discord-input px-3 py-2 text-sm">
                            <option value="">{t('追加するメンバーを選択')}</option>
                            {eligibleMembers.map((member) => <option key={member.userId} value={member.userId}>{member.user.displayName}</option>)}
                          </select>
                          <button type="button" onClick={() => { void addPrivateMember(); }} disabled={!memberToAdd || busy} className="rounded bg-discord-accent px-3 py-2 text-sm text-white disabled:opacity-40">{t('追加')}</button>
                        </div>
                        <ul className="space-y-1">
                          {channelMembers.map((member) => (
                            <li key={member.id} className="flex items-center justify-between gap-3 rounded bg-discord-sidebar px-3 py-2 text-sm text-discord-text">
                              <span>{member.displayName}{member.id === currentUser?.id ? t('（自分）') : ''}</span>
                              <button
                                type="button"
                                onClick={() => setConfirmation({
                                  kind: 'remove-member',
                                  channelId: selectedChannel.id,
                                  userId: member.id,
                                  label: member.id === currentUser?.id
                                    ? t('自分をこの非公開チャンネルから削除します。直ちに閲覧できなくなります。')
                                    : t('{name}をこの非公開チャンネルから削除します。', { name: member.displayName }),
                                  self: member.id === currentUser?.id,
                                })}
                                className="rounded px-2 py-1 text-xs text-discord-red hover:bg-discord-red hover:text-white"
                              >
                                {t('削除')}
                              </button>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </section>
                  <section className="rounded border border-discord-red/50 p-4">
                    <h3 className="font-medium text-discord-red">{t('危険な操作')}</h3>
                    <button
                      type="button"
                      onClick={() => setConfirmation({
                        kind: 'delete-channel',
                        id: selectedChannel.id,
                        label: selectedChannel.type === 'voice'
                          ? t('音声チャンネル「{name}」を削除します。この操作は元に戻せません。', { name: selectedChannel.name })
                          : t('チャンネル「{name}」と履歴を削除します。この操作は元に戻せません。', { name: selectedChannel.name }),
                      })}
                      className="mt-3 rounded bg-discord-red px-3 py-2 text-sm text-white"
                    >
                      {t('チャンネルを削除')}
                    </button>
                  </section>
                </>
              ) : <p className="text-sm text-discord-muted">{t('編集できるチャンネルがありません。')}</p>}
            </div>
          )}

          {tab === 'categories' && (
            <form onSubmit={submitCategory} className="space-y-4">
              <label className="block text-sm text-discord-text">
                {t('操作するカテゴリー')}
                <select
                  value={selectedCategoryId}
                  onChange={(event) => {
                    setSelectedCategoryId(event.target.value);
                    if (!event.target.value) { setCategoryName(''); setCategoryPosition('0'); }
                  }}
                  className="mt-1 w-full rounded bg-discord-input px-3 py-2"
                >
                  <option value="">{t('新しいカテゴリー')}</option>
                  {categories.map((category) => <option key={category.id} value={category.id}>{category.name}</option>)}
                </select>
              </label>
              <label className="block text-sm text-discord-text">
                {t('名前')}
                <input required maxLength={100} value={categoryName} onChange={(event) => setCategoryName(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2" />
              </label>
              <label className="block text-sm text-discord-text">
                {t('位置')}
                <input required type="number" min={0} max={1_000_000} value={categoryPosition} onChange={(event) => setCategoryPosition(event.target.value)} className="mt-1 w-full rounded bg-discord-input px-3 py-2" />
              </label>
              <div className="flex items-center justify-between gap-3">
                {selectedCategory ? (
                  <button type="button" onClick={() => setConfirmation({ kind: 'delete-category', id: selectedCategory.id, label: t('カテゴリー「{name}」を削除します。所属チャンネルはカテゴリーなしへ移動します。', { name: selectedCategory.name }) })} className="rounded px-3 py-2 text-sm text-discord-red hover:bg-discord-red hover:text-white">{t('カテゴリーを削除')}</button>
                ) : <span />}
                <button type="submit" disabled={busy || !categoryName.trim()} className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-40">
                  {busy ? t('保存中…') : selectedCategory ? t('カテゴリーを更新') : t('カテゴリーを作成')}
                </button>
              </div>
            </form>
          )}

          {tab === 'permissions' && (
            <PermissionOverrideManager
              key={`${workspaceId}:${authorizationRefreshVersion}`}
              workspaceId={workspaceId}
              channels={manageableChannels}
              categories={categories}
              members={workspaceMembers}
              onChanged={refreshWorkspace}
            />
          )}
        </div>
      )}
    </Dialog>
  );
}

function ChannelForm({ form, setForm, categories, submit, busy, submitLabel, isEditing = false }: {
  form: ChannelFormState;
  setForm: React.Dispatch<React.SetStateAction<ChannelFormState>>;
  categories: Array<{ id: string; name: string }>;
  submit: (event: React.FormEvent) => void;
  busy: boolean;
  submitLabel: string;
  isEditing?: boolean;
}) {
  const t = useT();
  return (
    <form onSubmit={submit} className="space-y-4">
      <label className="block text-sm text-discord-text">
        {t('名前')}
        <input required maxLength={100} value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} className="mt-1 w-full rounded bg-discord-input px-3 py-2" />
      </label>
      <label className="block text-sm text-discord-text">
        {t('トピック')}
        <textarea maxLength={500} value={form.topic} onChange={(event) => setForm((current) => ({ ...current, topic: event.target.value }))} className="mt-1 w-full rounded bg-discord-input px-3 py-2" rows={2} />
      </label>
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm text-discord-text">
          {t('カテゴリー')}
          <select value={form.categoryId} onChange={(event) => setForm((current) => ({ ...current, categoryId: event.target.value }))} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
            <option value="">{t('カテゴリーなし')}</option>
            {categories.map((category) => <option key={category.id} value={category.id}>{category.name}</option>)}
          </select>
        </label>
        <label className="block text-sm text-discord-text">
          {t('位置')}
          <input required type="number" min={0} max={1_000_000} value={form.position} onChange={(event) => setForm((current) => ({ ...current, position: event.target.value }))} className="mt-1 w-full rounded bg-discord-input px-3 py-2" />
        </label>
      </div>
      {!isEditing && (
        <label className="block text-sm text-discord-text">
          {t('種類')}
          <select value={form.type} onChange={(event) => setForm((current) => ({ ...current, type: event.target.value as ChannelFormState['type'] }))} className="mt-1 w-full rounded bg-discord-input px-3 py-2">
            <option value="text">{t('テキスト')}</option>
            <option value="announcement">{t('アナウンス')}</option>
            <option value="voice">{t('音声')}</option>
            <option value="forum">{t('フォーラム')}</option>
          </select>
        </label>
      )}
      <label className="flex items-start gap-3 rounded bg-discord-bg p-3 text-sm text-discord-text">
        <input type="checkbox" checked={form.isPrivate} onChange={(event) => setForm((current) => ({ ...current, isPrivate: event.target.checked }))} className="mt-0.5 h-4 w-4 accent-discord-accent" />
        <span>
          {t('非公開チャンネル')}
          <span className="mt-1 block text-xs text-discord-muted">{t('非公開にすると、保存した管理者だけが最初のメンバーになります。')}</span>
        </span>
      </label>
      <div className="flex justify-end">
        <button type="submit" disabled={busy || !form.name.trim()} className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
          {busy ? t('保存中…') : submitLabel}
        </button>
      </div>
    </form>
  );
}
