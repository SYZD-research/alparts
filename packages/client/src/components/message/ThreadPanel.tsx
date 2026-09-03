import type { Message } from '@alparts/shared';
import { useMessageStore } from '../../stores/message.store';
import { Dialog } from '../ui/Dialog';
import { userFacingMessageText } from '../../services/message-display';

interface ThreadPanelProps {
  channelId: string;
  root: Message | null;
  replies: Message[];
  onClose: () => void;
}

export function ThreadPanel({ channelId, root, replies, onClose }: ThreadPanelProps) {
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
      title="返信スレッド"
      size="md"
    >
      {root && (
        <div className="space-y-4">
          <ThreadMessage message={root} label="元のメッセージ" />
          <section aria-labelledby="loaded-thread-replies-heading">
            <div className="mb-2 flex items-center justify-between gap-3">
              <h3 id="loaded-thread-replies-heading" className="font-semibold text-white">
                返信
              </h3>
              <button
                type="button"
                onClick={reply}
                disabled={root.type === 'delete'}
                className="rounded bg-discord-accent px-3 py-2 text-sm text-white disabled:opacity-40"
              >
                このスレッドに返信
              </button>
            </div>
            {replies.length === 0 ? (
              <p className="rounded bg-discord-input px-3 py-4 text-sm text-discord-muted">このメッセージへの返信はまだありません。</p>
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
  return (
    <article className="rounded border border-discord-hover bg-discord-bg/40 px-3 py-2">
      {label && <p className="mb-1 text-xs font-medium text-discord-accent">{label}</p>}
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-medium text-white">{message.author?.displayName || '不明なユーザー'}</span>
        <time dateTime={message.createdAt} className="text-xs text-discord-muted">{formatMessageTime(message.createdAt)}</time>
      </div>
      <p className="mt-1 whitespace-pre-wrap break-words text-sm text-discord-text">
        {message.type === 'delete' ? '削除されたメッセージ' : userFacingMessageText(message.content || '') || '（本文なし）'}
      </p>
    </article>
  );
}

function formatMessageTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '日時不明' : date.toLocaleString('ja-JP');
}
