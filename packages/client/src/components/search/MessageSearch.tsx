import { useEffect, useMemo, useRef, useState } from 'react';
import { useChannelStore } from '../../stores/channel.store';
import { useMessageStore } from '../../stores/message.store';
import { searchLoadedMessages } from '../../stores/search-loaded-messages';

export function MessageSearch() {
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
    setIsOpen(false);
    window.setTimeout(() => {
      document.getElementById(`message-${messageId}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }, 100);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className="fixed right-4 top-2 z-30 rounded bg-discord-input px-3 py-1 text-xs text-discord-muted hover:text-discord-text"
        aria-label="読み込み済みメッセージを検索"
      >
        検索 <span className="ml-2 opacity-70">Ctrl/⌘ K</span>
      </button>
      {isOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[10vh]"
          role="dialog"
          aria-modal="true"
          aria-label="読み込み済みメッセージを検索"
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
                placeholder="この端末で読み込み済みのメッセージを検索"
                aria-label="検索語"
              />
              <p className="mt-2 text-xs text-discord-muted">検索語や復号済み本文はサーバーへ送信されません。</p>
            </div>
            <div className="overflow-y-auto p-2">
              {query.trim() && results.length === 0 && (
                <p className="p-6 text-center text-sm text-discord-muted">読み込み済みメッセージに一致しません</p>
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
