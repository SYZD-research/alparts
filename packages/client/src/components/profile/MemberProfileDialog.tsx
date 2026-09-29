import { useCallback, useEffect, useState } from 'react';
import type { MemberProfile } from '@alparts/shared';
import { api } from '../../services/api';
import { useUiStore } from '../../stores/ui.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { Dialog } from '../ui/Dialog';
import { UserAvatar } from '../user/UserAvatar';
import { profileErrorMessage } from './profile-model';

export function MemberProfileDialog() {
  const target = useUiStore((state) => state.profileTarget);
  const close = useUiStore((state) => state.closeMemberProfile);
  const loadMembers = useWorkspaceStore((state) => state.loadMembers);
  const [profile, setProfile] = useState<MemberProfile | null>(null);
  // Confirmation is remembered only while this profile stays open.
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!target) return;
    try {
      setProfile(await api.getMemberProfile(target.workspaceId, target.userId));
    } catch (caught) {
      setError(profileErrorMessage(caught));
    }
  }, [target]);

  useEffect(() => {
    setProfile(null);
    setRevealed(false);
    setError(null);
    void load();
  }, [load]);

  const act = async (operation: () => Promise<unknown>) => {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      await operation();
      await Promise.all([load(), loadMembers(target.workspaceId)]);
    } catch (caught) {
      setError(profileErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={target !== null} onClose={() => { if (!busy) close(); }} title={profile?.displayName ?? 'プロフィール'} size="sm">
      {!profile || !target ? (
        <p className="py-6 text-center text-discord-muted">{error ?? '読み込み中…'}</p>
      ) : (
        <MemberProfileView
          profile={profile}
          revealed={revealed}
          busy={busy}
          error={error}
          target={target}
          act={act}
          onReveal={() => setRevealed(true)}
          onClose={close}
        />
      )}
    </Dialog>
  );
}

/**
 * While a warned profile is not yet confirmed, neither the picture nor the
 * self-introduction is rendered at all.
 */
export function MemberProfileView({ profile, revealed, busy, error, target, act, onReveal, onClose }: {
  profile: MemberProfile;
  revealed: boolean;
  busy: boolean;
  error: string | null;
  target: { workspaceId: string; userId: string };
  act: (operation: () => Promise<unknown>) => Promise<void>;
  onReveal: () => void;
  onClose: () => void;
}) {
  if (profile.flagged && !revealed) {
    return (
      <div className="space-y-4">
        <p role="alert" className="rounded border border-discord-red/60 bg-discord-red/10 p-3 text-sm text-discord-text">
          管理者がこのユーザーのプロフィールを<strong>なりすまし・及び悪質なサービスへの誘導</strong>とマークしています。それでも見ますか？
        </p>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">閉じる</button>
          <button type="button" onClick={onReveal} className="rounded bg-discord-red px-3 py-2 text-sm font-medium text-white">見る</button>
        </div>
        <ManagerActions profile={profile} busy={busy} act={act} target={target} />
        {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <UserAvatar displayName={profile.displayName} avatarUrl={profile.avatarUrl} size="lg" />
        <p className="min-w-0 break-words text-lg font-semibold text-white">{profile.displayName}</p>
      </div>
      {profile.flagged && (
        <p className="rounded bg-discord-red/10 px-3 py-2 text-xs text-discord-red">
          管理者がこのプロフィールに警告を付けています。リンクや連絡先の誘導に注意してください。
        </p>
      )}
      {profile.bio ? (
        <p className="whitespace-pre-wrap break-words text-sm text-discord-text">{profile.bio}</p>
      ) : (
        <p className="text-sm text-discord-muted">自己紹介はありません。</p>
      )}
      <ManagerActions profile={profile} busy={busy} act={act} target={target} />
      {error && <p role="alert" className="text-sm text-discord-red">{error}</p>}
    </div>
  );
}

function ManagerActions({ profile, busy, act, target }: {
  profile: MemberProfile;
  busy: boolean;
  act: (operation: () => Promise<unknown>) => Promise<void>;
  target: { workspaceId: string; userId: string };
}) {
  const [confirmFlag, setConfirmFlag] = useState(false);
  if (!profile.canManageFlag) return null;
  const button = 'rounded px-3 py-1.5 text-sm disabled:opacity-50';
  return (
    <section className="space-y-2 border-t border-discord-hover pt-3 text-sm">
      <p className="text-xs text-discord-muted">管理者の操作（このワークスペースのみ）</p>
      {profile.flagged ? (
        <div className="flex flex-wrap gap-2">
          {profile.appealStatus === 'pending' && <p className="w-full text-discord-yellow">このユーザーから警告の解除を依頼されています。</p>}
          <button type="button" disabled={busy} onClick={() => { void act(() => api.unflagProfile(target.workspaceId, target.userId)); }} className={`${button} bg-discord-hover text-white`}>
            {profile.appealStatus === 'pending' ? '依頼を認めて警告を外す' : '警告を外す'}
          </button>
          {profile.appealStatus === 'pending' && (
            <button type="button" disabled={busy} onClick={() => { void act(() => api.denyProfileAppeal(target.workspaceId, target.userId)); }} className={`${button} text-discord-red hover:bg-discord-red/10`}>
              依頼を認めない
            </button>
          )}
        </div>
      ) : confirmFlag ? (
        <div className="space-y-2">
          <p>このワークスペースのメンバーがこのプロフィールを見る前に、確認を表示します。よろしいですか？</p>
          <div className="flex gap-2">
            <button type="button" disabled={busy} onClick={() => { setConfirmFlag(false); void act(() => api.flagProfile(target.workspaceId, target.userId)); }} className={`${button} bg-discord-red text-white`}>警告を付ける</button>
            <button type="button" disabled={busy} onClick={() => setConfirmFlag(false)} className={`${button} text-discord-muted hover:bg-discord-hover`}>やめる</button>
          </div>
        </div>
      ) : (
        <button type="button" disabled={busy} onClick={() => setConfirmFlag(true)} className={`${button} text-discord-red hover:bg-discord-red/10`}>
          なりすまし・悪質なサービスへの誘導として警告を付ける
        </button>
      )}
    </section>
  );
}
