import { useEffect, useState } from 'react';
import { Dialog } from '../ui/Dialog';
import { useUiStore } from '../../stores/ui.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { useAuthStore } from '../../stores/auth.store';
import { useDmStore } from '../../stores/dm.store';
import { useChannelStore } from '../../stores/channel.store';
import { useT } from '../../i18n';

export function DmComposerDialog() {
  const t = useT();
  const workspaceId = useUiStore((state) => state.dmComposerWorkspaceId);
  const initialMemberIds = useUiStore((state) => state.dmComposerInitialMemberIds);
  const close = useUiStore((state) => state.closeDmComposer);
  const members = useWorkspaceStore((state) => state.members);
  const user = useAuthStore((state) => state.user);
  const createOrReuseDm = useDmStore((state) => state.createOrReuseDm);
  const loadChannels = useChannelStore((state) => state.loadChannels);
  const setActiveChannel = useChannelStore((state) => state.setActiveChannel);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setSelectedIds(initialMemberIds);
    setError(null);
  }, [initialMemberIds, workspaceId]);

  const eligibleMembers = members.filter((member) => member.userId !== user?.id);
  const toggleMember = (memberId: string) => {
    setSelectedIds((current) => current.includes(memberId)
      ? current.filter((id) => id !== memberId)
      : current.length < 19 ? [...current, memberId] : current);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!workspaceId || !user || selectedIds.length === 0 || isSubmitting) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const conversation = await createOrReuseDm(workspaceId, user.id, selectedIds);
      await loadChannels(workspaceId);
      setActiveChannel(conversation.channelId);
      close();
    } catch {
      setError(t('DMを開けませんでした。もう一度お試しください。'));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog
      open={Boolean(workspaceId)}
      onClose={close}
      title={t('ダイレクトメッセージを開始')}
      description={t('同じ相手との1対1 DMがある場合は既存チャンネルを開きます。')}
    >
      <form onSubmit={submit} className="space-y-4">
        {error && <div role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{error}</div>}
        <fieldset>
          <legend className="mb-2 text-sm font-medium text-discord-text">{t('メンバー（最大19人）')}</legend>
          <div className="max-h-80 space-y-1 overflow-y-auto rounded bg-discord-bg p-2">
            {eligibleMembers.length === 0 && <p className="p-3 text-sm text-discord-muted">{t('選択できるメンバーがいません')}</p>}
            {eligibleMembers.map((member) => (
              <label key={member.userId} className="flex cursor-pointer items-center gap-3 rounded px-3 py-2 hover:bg-discord-hover">
                <input
                  type="checkbox"
                  checked={selectedIds.includes(member.userId)}
                  onChange={() => toggleMember(member.userId)}
                  disabled={!selectedIds.includes(member.userId) && selectedIds.length >= 19}
                  className="h-4 w-4 accent-discord-accent"
                />
                <span className="flex h-8 w-8 items-center justify-center rounded-full bg-discord-accent text-sm font-bold text-white">
                  {member.user.displayName.slice(0, 1).toUpperCase()}
                </span>
                <span className="text-sm text-discord-text">{member.user.displayName}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={close} className="rounded px-4 py-2 text-sm text-discord-muted hover:bg-discord-hover">{t('キャンセル')}</button>
          <button
            type="submit"
            disabled={selectedIds.length === 0 || isSubmitting}
            className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? t('準備中…') : selectedIds.length === 1 ? t('DMを開く') : t('グループDMを作成')}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
