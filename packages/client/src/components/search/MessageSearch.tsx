import { useEffect, useMemo, useRef, useState } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { searchLoadedMessages } from '../../stores/search-loaded-messages';

interface MessageSearchProps {
  membersOpen: boolean;
  membersAvailable: boolean;
  onToggleMembers: () => void;
  showToolbar: boolean;
  onNavigateToChat: () => void;
}

export function MessageSearch({ membersOpen, membersAvailable, onToggleMembers, showToolbar, onNavigateToChat }: MessageSearchProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const channels = useChannelStore((state) => state.channels);
  const setActiveChannel = useChannelStore((state) => state.setActiveChannel);
  const messagesByChannel = useMessageStore((state) => state.messagesByChannel);
  const results = useMemo(
    () => searchLoadedMessages(query, messagesByChannel, channels),
    [channels, messagesByChannel, query],
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
        aria-label="メンバー一覧"
        title="メンバー一覧"
        aria-expanded={membersOpen}
        aria-controls={membersOpen ? 'member-list' : undefined}
        className={`flex h-11 w-11 items-center justify-center rounded hover:bg-discord-hover disabled:opacity-40 ${membersOpen ? 'text-white bg-discord-hover' : 'text-discord-muted hover:text-white'}`}
      >
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
          <circle cx="9" cy="8" r="3" /><path d="M3 20v-2a6 6 0 0 1 12 0v2M16 5a3 3 0 0 1 0 6m2 3a5 5 0 0 1 3 4v2" />
        </svg>
      </button>
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className="flex h-11 min-w-11 items-center justify-center gap-2 rounded px-2 text-xs text-discord-muted hover:bg-discord-hover hover:text-white"
        aria-label="メッセージを検索"
        title="メッセージを検索"
      >
        <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5" /></svg>
        <span className="hidden md:inline">検索 <span className="ml-2 opacity-70">Ctrl/⌘ K</span></span>
      </button>
      </div>
      {isOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[10vh]"
          role="dialog"
          aria-modal="true"
          aria-label="メッセージを検索"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setIsOpen(false);
          }}
        >
          <div className="flex max-h-[75vh] w-full max-w-2xl flex-col overflow-hidden rounded-lg bg-discord-sidebar shadow-2xl">
            <div className="border-b border-discord-hover p-3">
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="w-full rounded bg-discord-input px-4 py-3 text-discord-text outline-none focus:ring-1 focus:ring-discord-accent"
                placeholder="メッセージを検索"
                aria-label="検索語"
              />
            </div>
            <div className="overflow-y-auto p-2">
              {query.trim() && results.length === 0 && (
                <p className="p-6 text-center text-sm text-discord-muted">一致するメッセージがありません</p>
              )}
              {!query.trim() && (
                <p className="p-6 text-center text-sm text-discord-muted">本文、投稿者、チャンネル名で検索できます</p>
              )}
              {results.map((result) => (
                <button
                  key={`${result.channelId}:${result.messageId}`}
                  type="button"
                  onClick={() => selectResult(result.channelId, result.messageId)}
                  className="w-full rounded px-3 py-2 text-left hover:bg-discord-hover"
                >
                  <div className="flex items-center gap-2 text-xs text-discord-muted">
                    <span>#{result.channelName}</span>
                    <span>{result.authorName}</span>
                    <time>{new Date(result.createdAt).toLocaleString('ja-JP')}</time>
                  </div>
                  <p className="mt-1 line-clamp-2 break-words text-sm text-discord-text">{result.content}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
