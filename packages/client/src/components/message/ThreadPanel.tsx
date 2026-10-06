import type { Message } from '@alparts/shared';
import { useMessageStore } from '../../stores/message.store';
import { Dialog } from '../ui/Dialog';
import { userFacingMessageText } from '../../services/message-display';
import { intlLocale, t, useT } from '../../i18n';

interface ThreadPanelProps {
  channelId: string;
  root: Message | null;
  replies: Message[];
  onClose: () => void;
}

export function ThreadPanel({ channelId, root, replies, onClose }: ThreadPanelProps) {
  const t = useT();
  const setReplyTarget = useMessageStore((state) => state.setReplyTarget);

  const reply = () => {
    if (!root || root.type === 'delete') return;
    setReplyTarget(channelId, root);
    onClose();
    requestAnimationFrame(() => document.getElementById(`message-input-${channelId}`)?.focus());
  };

  return (
    <Dialog
      open={Boolean(root)}
      onClose={onClose}
      title={t('返信スレッド')}
      size="md"
    >
      {root && (
        <div className="space-y-4">
          <ThreadMessage message={root} label={t('元のメッセージ')} />
          <section aria-labelledby="loaded-thread-replies-heading">
            <div className="mb-2 flex items-center justify-between gap-3">
              <h3 id="loaded-thread-replies-heading" className="font-semibold text-white">
                {t('返信')}
              </h3>
              <button
                type="button"
                onClick={reply}
                disabled={root.type === 'delete'}
                className="rounded bg-discord-accent px-3 py-2 text-sm text-white disabled:opacity-40"
              >
                {t('このスレッドに返信')}
              </button>
            </div>
            {replies.length === 0 ? (
              <p className="rounded bg-discord-input px-3 py-4 text-sm text-discord-muted">{t('このメッセージへの返信はまだありません。')}</p>
            ) : (
              <ol className="space-y-2">
                {replies.map((message) => (
                  <li key={message.id}><ThreadMessage message={message} /></li>
                ))}
              </ol>
            )}
          </section>
        </div>
      )}
    </Dialog>
  );
}

function ThreadMessage({ message, label }: { message: Message; label?: string }) {
  const t = useT();
  return (
    <article className="rounded border border-discord-hover bg-discord-bg/40 px-3 py-2">
      {label && <p className="mb-1 text-xs font-medium text-discord-accent">{label}</p>}
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-medium text-white">{message.author?.displayName || t('不明なユーザー')}</span>
        <time dateTime={message.createdAt} className="text-xs text-discord-muted">{formatMessageTime(message.createdAt)}</time>
      </div>
      <p className="mt-1 whitespace-pre-wrap break-words text-sm text-discord-text">
        {message.type === 'delete' ? t('削除されたメッセージ') : userFacingMessageText(message.content || '') || t('（本文なし）')}
      </p>
    </article>
  );
}

function formatMessageTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('日時不明') : date.toLocaleString(intlLocale());
}
