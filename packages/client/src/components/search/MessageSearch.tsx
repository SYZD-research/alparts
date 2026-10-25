import { useEffect, useMemo, useRef, useState } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { searchLoadedMessages } from '../../stores/search-loaded-messages';
import { formatDateTime } from '../../stores/date-format';
import { Icon } from '../ui/Icon';
import { useT } from '../../i18n';

interface MessageSearchProps {
  membersOpen: boolean;
  membersAvailable: boolean;
  onToggleMembers: () => void;
  showToolbar: boolean;
  onNavigateToChat: () => void;
}

export function MessageSearch({ membersOpen, membersAvailable, onToggleMembers, showToolbar, onNavigateToChat }: MessageSearchProps) {
  const t = useT();
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const channels = useChannelStore((state) => state.channels);
  const setActiveChannel = useChannelStore((state) => state.setActiveChannel);
  const messagesByChannel = useMessageStore((state) => state.messagesByChannel);
  const members = useWorkspaceStore((state) => state.members);
  const results = useMemo(
    () => searchLoadedMessages(query, messagesByChannel, channels, members),
    [channels, members, messagesByChannel, query],
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === 'k') {
        if (document.querySelector('[role="dialog"]')) return;
        event.preventDefault();
        setIsOpen(true);
      } else if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    if (isOpen) requestAnimationFrame(() => inputRef.current?.focus());
    else setQuery('');
  }, [isOpen]);

  const selectResult = (channelId: string, messageId: string) => {
    setActiveChannel(channelId);
    onNavigateToChat();
    setIsOpen(false);
    window.setTimeout(() => {
      document.getElementById(`message-${messageId}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }, 100);
  };

  return (
    <>
      <div className="chat-toolbar fixed right-2 top-0 z-40 flex h-12 items-center gap-1" hidden={!showToolbar}>
      <button
        id="members-toggle"
        type="button"
        onClick={onToggleMembers}
        disabled={!membersAvailable}
        aria-label={t('メンバー一覧')}
        title={t('メンバー一覧')}
        aria-expanded={membersOpen}
        aria-controls={membersOpen ? 'member-list' : undefined}
        className={`flex h-11 w-11 items-center justify-center rounded-lg transition-colors hover:bg-hover disabled:opacity-40 ${membersOpen ? 'bg-selected text-ink-strong' : 'text-muted hover:text-ink-strong'}`}
      >
        <Icon name="members" size={20} />
      </button>
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className="flex h-11 min-w-11 items-center justify-center gap-2 rounded-lg px-2 text-xs text-muted transition-colors hover:bg-hover hover:text-ink-strong md:h-8 md:border md:border-line md:bg-panel md:pl-2.5 md:pr-1.5 md:hover:bg-hover"
        aria-label={t('メッセージを検索')}
        title={t('メッセージを検索')}
      >
        <Icon name="search" />
        <span className="hidden md:inline">{t('検索')}</span>
        <kbd className="ml-4 hidden rounded-md border border-line bg-canvas px-1.5 py-0.5 font-sans text-[10px] text-muted md:inline">Ctrl/⌘ K</kbd>
      </button>
      </div>
      {isOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[10vh] backdrop-blur-[2px]"
          role="dialog"
          aria-modal="true"
          aria-label={t('メッセージを検索')}
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setIsOpen(false);
          }}
        >
          <div className="flex max-h-[75vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-2xl shadow-black/50">
            <div className="flex items-center gap-3 border-b border-line px-4 text-muted focus-within:text-ink-soft">
              <Icon name="search" size={20} />
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="h-14 w-full bg-transparent text-[15px] text-ink outline-hidden"
                placeholder={t('メッセージを検索')}
                aria-label={t('検索語')}
              />
            </div>
            <div className="overflow-y-auto p-2">
              {query.trim() && results.length === 0 && (
                <p className="p-8 text-center text-sm text-muted">{t('一致するメッセージがありません')}</p>
              )}
              {!query.trim() && (
                <p className="p-8 text-center text-sm text-muted">{t('本文、投稿者、チャンネル名で検索できます')}</p>
              )}
              {results.map((result) => (
                <button
                  key={`${result.channelId}:${result.messageId}`}
                  type="button"
                  onClick={() => selectResult(result.channelId, result.messageId)}
                  className="w-full rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-hover"
                >
                  <div className="flex items-center gap-2 text-xs text-muted">
                    <span className="font-medium text-ink-soft">#{result.channelName}</span>
                    <span>{result.authorName}</span>
                    <time>{formatDateTime(result.createdAt)}</time>
                  </div>
                  <p className="mt-1 line-clamp-2 wrap-break-word text-sm text-ink">{result.content}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
