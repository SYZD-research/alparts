import { useEffect, useRef, useState } from 'react';
import type { OwnProfile } from '@alparts/shared';
import { api } from '../../services/api';
import { decodeAvatarSource, renderAvatar } from '../../services/avatar-image';
import { useAuthStore } from '../../stores/auth.store';
import { useUiStore } from '../../stores/ui.store';
import { Dialog } from '../ui/Dialog';
import { UserAvatar } from '../user/UserAvatar';
import type { SourceCrop } from './avatar-crop-model';
import { AvatarCropper } from './AvatarCropper';
import { bioLengthStatus, profileErrorMessage } from './profile-model';
import { useT } from '../../i18n';

export function ProfileSettingsDialog() {
  const t = useT();
  const open = useUiStore((state) => state.isProfileSettingsOpen);
  const close = useUiStore((state) => state.closeProfileSettings);
  const [profile, setProfile] = useState<OwnProfile | null>(null);
  const [displayName, setDisplayName] = useState('');
  const [bio, setBio] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'notice'; text: string } | null>(null);
  const [confirmAppeal, setConfirmAppeal] = useState<string | null>(null);
  const [cropping, setCropping] = useState<ImageBitmap | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const apply = (next: OwnProfile) => {
    setProfile(next);
    setDisplayName(next.displayName);
    setBio(next.bio ?? '');
    const user = useAuthStore.getState().user;
    if (user) useAuthStore.setState({ user: { ...user, displayName: next.displayName, avatarUrl: next.avatarUrl } });
  };

  // The decoded picture is released as soon as it is no longer being edited.
  useEffect(() => () => cropping?.close(), [cropping]);

  useEffect(() => {
    if (!open) {
      setCropping(null);
      return;
    }
    setMessage(null);
    setConfirmAppeal(null);
    let active = true;
    void api.getOwnProfile()
      .then((next) => { if (active) apply(next); })
      .catch(() => { if (active) setMessage({ kind: 'error', text: t('プロフィールを読み込めませんでした。もう一度お試しください。') }); });
    return () => { active = false; };
  }, [open]);

  const run = async (operation: () => Promise<void>, notice: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await operation();
      setMessage({ kind: 'notice', text: notice });
    } catch (error) {
      setMessage({ kind: 'error', text: profileErrorMessage(error) });
    } finally {
      setBusy(false);
    }
  };

  const save = () => run(async () => {
    apply(await api.updateOwnProfile({ displayName, bio }));
  }, t('プロフィールを保存しました。'));

  const chooseImage = async (file: File | undefined) => {
    if (!file) return;
    setMessage(null);
    try {
      setCropping(await decodeAvatarSource(file));
    } catch (error) {
      setMessage({ kind: 'error', text: profileErrorMessage(error) });
    }
  };

  const saveImage = (bitmap: ImageBitmap, crop: SourceCrop) => run(async () => {
    await api.uploadAvatar(await renderAvatar(bitmap, crop));
    apply(await api.getOwnProfile());
    setCropping(null);
  }, t('画像を変更しました。'));

  const removeImage = () => run(async () => {
    await api.removeAvatar();
    apply(await api.getOwnProfile());
  }, t('画像を削除しました。'));

  const appeal = (workspaceId: string) => run(async () => {
    await api.requestProfileAppeal(workspaceId);
    setConfirmAppeal(null);
    apply(await api.getOwnProfile());
  }, t('管理者に警告の解除を依頼しました。'));

  const length = bioLengthStatus(bio);

  return (
    <Dialog open={open} onClose={() => { if (!busy) close(); }} title={t('プロフィール')} size="sm">
      {!profile ? (
        <p className="py-6 text-center text-discord-muted">{message?.text ?? t('読み込み中…')}</p>
      ) : cropping ? (
        <div className="space-y-3">
          <AvatarCropper bitmap={cropping} busy={busy} onConfirm={(crop) => { void saveImage(cropping, crop); }} onCancel={() => setCropping(null)} />
          {message?.kind === 'error' && <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">{message.text}</p>}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <UserAvatar displayName={profile.displayName} avatarUrl={profile.avatarUrl} size="lg" />
            <div className="flex flex-col gap-2">
              <input
                ref={fileInput}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={(event) => { void chooseImage(event.target.files?.[0]); event.target.value = ''; }}
              />
              <button type="button" disabled={busy} onClick={() => fileInput.current?.click()} className="rounded bg-discord-hover px-3 py-1.5 text-sm text-white disabled:opacity-50">
                {t('画像を選ぶ')}
              </button>
              {profile.avatarUrl && (
                <button type="button" disabled={busy} onClick={() => { void removeImage(); }} className="rounded px-3 py-1.5 text-sm text-discord-red hover:bg-discord-red/10 disabled:opacity-50">
                  {t('画像を削除')}
                </button>
              )}
              <p className="text-xs text-discord-muted">{t('PNG・JPEG・WebP（5MBまで）')}</p>
            </div>
          </div>

          <label className="block text-sm text-discord-muted">
            {t('表示名')}
            <input
              value={displayName}
              maxLength={100}
              onChange={(event) => setDisplayName(event.target.value)}
              className="mt-1 block w-full rounded bg-discord-input px-3 py-2 text-discord-text"
            />
          </label>

          <label className="block text-sm text-discord-muted">
            {t('自己紹介')}
            <textarea
              value={bio}
              rows={5}
              onChange={(event) => setBio(event.target.value)}
              className="mt-1 block w-full resize-none rounded bg-discord-input px-3 py-2 text-discord-text"
            />
            <span className={`mt-1 block text-right text-xs ${length.ok ? 'text-discord-muted' : 'text-discord-red'}`}>
              {t('{characters}/200文字・{lines}/5行', { characters: length.characters, lines: length.lines })}
            </span>
          </label>

          {message && (
            <p role={message.kind === 'error' ? 'alert' : 'status'} className={`rounded px-3 py-2 text-sm ${message.kind === 'error' ? 'bg-discord-red/15 text-discord-red' : 'bg-discord-hover text-discord-text'}`}>
              {message.text}
            </p>
          )}

          <div className="flex justify-end">
            <button
              type="button"
              disabled={busy || !length.ok || displayName.trim().length === 0}
              onClick={() => { void save(); }}
              className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {busy ? t('保存中…') : t('保存')}
            </button>
          </div>

          {profile.flags.length > 0 && (
            <section className="space-y-2 border-t border-discord-hover pt-4">
              {profile.flags.map((flag) => (
                <div key={flag.workspaceId} className="rounded border border-discord-yellow/40 bg-discord-yellow/10 p-3 text-sm text-discord-text">
                  <p>{t('「{workspace}」の管理者が、あなたのプロフィールの確認を必要としています。このワークスペースでは、ほかのメンバーが見る前に確認が表示されます。', { workspace: flag.workspaceName })}</p>
                  {flag.appealStatus === 'pending' && <p className="mt-2 text-discord-muted">{t('管理者に警告の解除を依頼しています。')}</p>}
                  {flag.appealStatus === 'denied' && <p className="mt-2 text-discord-muted">{t('解除の依頼は認められませんでした。')}</p>}
                  {flag.appealStatus === 'none' && flag.canAppeal && (
                    confirmAppeal === flag.workspaceId ? (
                      <div className="mt-2 space-y-2">
                        <p className="font-medium">{t('解除を依頼できるのは、すべてのワークスペースを通じて一度だけです。認められなかった場合、再び依頼することはできません。依頼しますか？')}</p>
                        <div className="flex gap-2">
                          <button type="button" disabled={busy} onClick={() => { void appeal(flag.workspaceId); }} className="rounded bg-discord-accent px-3 py-1.5 text-white disabled:opacity-50">{t('依頼する')}</button>
                          <button type="button" disabled={busy} onClick={() => setConfirmAppeal(null)} className="rounded px-3 py-1.5 text-discord-muted hover:bg-discord-hover">{t('やめる')}</button>
                        </div>
                      </div>
                    ) : (
                      <button type="button" disabled={busy} onClick={() => setConfirmAppeal(flag.workspaceId)} className="mt-2 rounded bg-discord-hover px-3 py-1.5 text-white disabled:opacity-50">
                        {t('プロフィールを見直したので、解除を依頼する')}
                      </button>
                    )
                  )}
                  {flag.appealStatus === 'none' && !flag.canAppeal && (
                    <p className="mt-2 text-discord-muted">
                      {profile.appealUsed
                        ? t('解除の依頼はすでに使用済みです。')
                        : t('プロフィールを変更すると、解除を一度だけ依頼できます。')}
                    </p>
                  )}
                </div>
              ))}
            </section>
          )}
        </div>
      )}
    </Dialog>
  );
}

