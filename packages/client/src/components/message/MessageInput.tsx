import { useState, useRef, useCallback, useEffect } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useDraftStore } from '../../stores/draft.store';
import { useOutboxStore } from '../../stores/outbox.store';
import { useAttachmentStore } from '../../stores/attachment.store';
import { getSocket } from '../../services/socket';
import { MAX_FILE_SIZE, MAX_MESSAGE_LENGTH } from '@alparts/shared';
import { ATTACHMENT_MAX_COUNT_PER_MESSAGE } from '../../services/attachment-crypto.service';
import { Dialog } from '../ui/Dialog';
import {
  insertPastedText,
  previewLargePaste,
  type LargePastePreview,
} from '../../stores/paste-preview-model';

interface Props {
  channelId: string;
}

interface PendingPaste {
  channelId: string;
  editMessageId: string | null;
  text: string;
  start: number;
  end: number;
  preview: LargePastePreview;
}

export function MessageInput({ channelId }: Props) {
  const [editContent, setEditContent] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);
  const [pendingPaste, setPendingPaste] = useState<PendingPaste | null>(null);
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [isOnline, setIsOnline] = useState(() => typeof navigator === 'undefined' || navigator.onLine);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const editMessage = useMessageStore((state) => state.editMessage);
  const sendMessage = useMessageStore((state) => state.sendMessage);
  const replyTarget = useMessageStore((state) => state.replyTargets[channelId]);
  const editTarget = useMessageStore((state) => state.editTargets[channelId]);
  const setReplyTarget = useMessageStore((state) => state.setReplyTarget);
  const setEditTarget = useMessageStore((state) => state.setEditTarget);
  const draft = useDraftStore((state) => state.drafts[channelId] || '');
  const draftError = useDraftStore((state) => state.errorsByChannel[channelId]);
  const loadDraft = useDraftStore((state) => state.loadDraft);
  const setDraft = useDraftStore((state) => state.setDraft);
  const clearDraft = useDraftStore((state) => state.clearDraft);
  const clearDraftError = useDraftStore((state) => state.clearError);
  const outboxItems = useOutboxStore((state) => state.items);
  const outboxError = useOutboxStore((state) => state.errorsByChannel[channelId]);
  const enqueue = useOutboxStore((state) => state.enqueue);
  const retry = useOutboxStore((state) => state.retry);
  const clearOutboxError = useOutboxStore((state) => state.clearError);
  const attachmentTasks = useAttachmentStore((state) => state.tasks);
  const startUploads = useAttachmentStore((state) => state.startUploads);
  const retryUpload = useAttachmentStore((state) => state.retryUpload);
  const resumeFailedUploads = useAttachmentStore((state) => state.resumeFailedUploads);
  const cancelUpload = useAttachmentStore((state) => state.cancelUpload);
  const dismissUpload = useAttachmentStore((state) => state.dismissUpload);
  const typingTimeout = useRef<ReturnType<typeof setTimeout>>();
  const lastTypingSent = useRef<number>(0);
  const content = editTarget ? editContent : draft;
  const channelOutboxItems = Object.values(outboxItems)
    .filter((item) => item.channelId === channelId)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  const channelAttachmentTasks = Object.values(attachmentTasks)
    .filter((task) => task.channelId === channelId);

  useEffect(() => {
    void loadDraft(channelId);
  }, [channelId, loadDraft]);

  useEffect(() => {
    setEditContent(editTarget?.content || '');
    if (editTarget) {
      setSelectedFiles([]);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }, [channelId, editTarget?.id]);

  useEffect(() => {
    setSelectedFiles([]);
    setAttachmentError(null);
    setPendingPaste(null);
    setPasteError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, [channelId]);

  useEffect(() => {
    const updateOnlineState = () => {
      const online = navigator.onLine;
      setIsOnline(online);
      if (online) resumeFailedUploads();
    };
    window.addEventListener('online', updateOnlineState);
    window.addEventListener('offline', updateOnlineState);
    return () => {
      window.removeEventListener('online', updateOnlineState);
      window.removeEventListener('offline', updateOnlineState);
    };
  }, [resumeFailedUploads]);

  useEffect(() => {
    lastTypingSent.current = 0;
    return () => {
      if (typingTimeout.current) clearTimeout(typingTimeout.current);
      getSocket()?.emit('typing:stop', { channelId });
    };
  }, [channelId]);

  const handleTyping = useCallback(() => {
    const socket = getSocket();
    if (!socket) return;

    const now = Date.now();
    if (now - lastTypingSent.current > 3000) {
      socket.emit('typing:start', { channelId });
      lastTypingSent.current = now;
    }

    if (typingTimeout.current) {
      clearTimeout(typingTimeout.current);
    }
    typingTimeout.current = setTimeout(() => {
      socket.emit('typing:stop', { channelId });
    }, 3000);
  }, [channelId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if ((!content.trim() && selectedFiles.length === 0) || isSending) return;
    if (editTarget && !content.trim()) return;

    setIsSending(true);
    setAttachmentError(null);
    try {
      if (editTarget) {
        await editMessage(editTarget.id, channelId, content.trim());
        setEditContent('');
        setEditTarget(channelId, null);
      } else if (selectedFiles.length > 0) {
        if (!isOnline) throw new Error('添付ファイルはオンライン時のみ送信できます');
        const message = await sendMessage(channelId, content.trim(), replyTarget?.id, undefined, true);
        const files = selectedFiles;
        // Register upload runtimes immediately after the durable base message.
        // Draft persistence must not delay or accidentally suppress the file
        // transfer path.
        void startUploads(message, files).catch((error: unknown) => {
          setAttachmentError(error instanceof Error ? error.message : '添付アップロードを開始できませんでした');
        });
        setSelectedFiles([]);
        if (fileInputRef.current) fileInputRef.current.value = '';
        await clearDraft(channelId);
        setReplyTarget(channelId, null);
      } else {
        await enqueue(channelId, content.trim(), replyTarget?.id);
        await clearDraft(channelId);
        setReplyTarget(channelId, null);
      }

      // Stop typing indicator
      const socket = getSocket();
      if (socket) {
        if (typingTimeout.current) clearTimeout(typingTimeout.current);
        socket.emit('typing:stop', { channelId });
      }
    } catch (error) {
      if (selectedFiles.length > 0) {
        setAttachmentError(error instanceof Error ? error.message : '添付ファイルを送信できませんでした');
      }
    } finally {
      setIsSending(false);
    }
  };

  const handleFilesSelected = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    setAttachmentError(null);
    if (files.length > ATTACHMENT_MAX_COUNT_PER_MESSAGE) {
      setAttachmentError(`添付ファイルは1メッセージ${ATTACHMENT_MAX_COUNT_PER_MESSAGE}件までです`);
      event.target.value = '';
      return;
    }
    const oversized = files.find((file) => file.size > MAX_FILE_SIZE);
    if (oversized) {
      setAttachmentError(`${oversized.name} は100MBを超えています`);
      event.target.value = '';
      return;
    }
    setSelectedFiles(files);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const handlePaste = (event: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const text = event.clipboardData.getData('text/plain');
    const preview = previewLargePaste(text);
    if (!preview) return;
    event.preventDefault();
    setPasteError(null);
    setPendingPaste({
      channelId,
      editMessageId: editTarget?.id || null,
      text,
      start: event.currentTarget.selectionStart ?? content.length,
      end: event.currentTarget.selectionEnd ?? content.length,
      preview,
    });
  };

  const closePastePreview = () => {
    setPendingPaste(null);
    requestAnimationFrame(() => textareaRef.current?.focus());
  };

  const applyPendingPaste = () => {
    if (!pendingPaste) return;
    if (pendingPaste.channelId !== channelId || pendingPaste.editMessageId !== (editTarget?.id || null)) {
      setPasteError('チャンネルまたは編集対象が変わったため、貼り付けを破棄しました');
      setPendingPaste(null);
      return;
    }
    const nextContent = insertPastedText(content, pendingPaste.text, pendingPaste.start, pendingPaste.end);
    if (nextContent.length > MAX_MESSAGE_LENGTH) return;
    const caret = Math.min(pendingPaste.start + pendingPaste.text.length, nextContent.length);
    if (editTarget) setEditContent(nextContent);
    else setDraft(channelId, nextContent);
    handleTyping();
    setPendingPaste(null);
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(caret, caret);
    });
  };

  const pastedResult = pendingPaste
    ? insertPastedText(content, pendingPaste.text, pendingPaste.start, pendingPaste.end)
    : '';

  return (
    <div className="px-4 pb-6 pt-2">
      <Dialog
        open={Boolean(pendingPaste)}
        onClose={closePastePreview}
        title="大量のテキストを貼り付けますか？"
        description="内容は送信されず、確認後に入力欄へ反映されます。プレビューは常にプレーンテキストです。"
        size="md"
      >
        {pendingPaste && (
          <div className="space-y-4">
            <p className="text-sm text-discord-muted">
              {pendingPaste.preview.byteCount.toLocaleString('ja-JP')} bytes・{pendingPaste.preview.lineCount.toLocaleString('ja-JP')}行
            </p>
            <section aria-label="貼り付け内容のプレビュー" className="rounded bg-discord-input p-3">
              <p className="mb-1 text-xs font-medium text-discord-muted">{pendingPaste.preview.omitted ? '先頭' : '内容'}</p>
              <pre className="max-h-44 overflow-auto whitespace-pre-wrap break-words text-sm text-discord-text">{pendingPaste.preview.head}</pre>
              {pendingPaste.preview.omitted && (
                <>
                  <p className="my-2 text-center text-xs text-discord-muted">…中間を省略…</p>
                  <p className="mb-1 text-xs font-medium text-discord-muted">末尾</p>
                  <pre className="max-h-44 overflow-auto whitespace-pre-wrap break-words text-sm text-discord-text">{pendingPaste.preview.tail}</pre>
                </>
              )}
            </section>
            {pastedResult.length > MAX_MESSAGE_LENGTH && (
              <p role="alert" className="rounded bg-discord-red/15 px-3 py-2 text-sm text-discord-red">
                反映後は{pastedResult.length.toLocaleString('ja-JP')}文字になり、上限{MAX_MESSAGE_LENGTH.toLocaleString('ja-JP')}文字を超えます。短くしてから貼り付けてください。
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={closePastePreview} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover">キャンセル</button>
              <button
                type="button"
                onClick={applyPendingPaste}
                disabled={pastedResult.length > MAX_MESSAGE_LENGTH}
                className="rounded bg-discord-accent px-4 py-2 text-sm text-white disabled:opacity-40"
              >
                入力欄へ反映
              </button>
            </div>
          </div>
        )}
      </Dialog>
      {(replyTarget || editTarget) && (
        <div className="flex items-center justify-between rounded-t-lg bg-discord-sidebar px-3 py-2 text-xs text-discord-muted">
          <span className="truncate">
            {editTarget
              ? `${editTarget.author.displayName} のメッセージを編集中`
              : `${replyTarget?.author.displayName} に返信中`}
          </span>
          <button
            type="button"
            onClick={() => {
              if (editTarget) {
                setEditTarget(channelId, null);
                setEditContent('');
              } else {
                setReplyTarget(channelId, null);
              }
            }}
            className="ml-3 text-discord-text hover:underline"
          >
            キャンセル
          </button>
        </div>
      )}
      {(draftError || outboxError || attachmentError || pasteError) && (
        <div role="alert" className="mb-2 flex items-center justify-between gap-3 rounded bg-discord-red/15 px-3 py-2 text-xs text-discord-red">
          <span>{draftError || outboxError || attachmentError || pasteError}</span>
          <button
            type="button"
            onClick={() => {
              clearDraftError(channelId);
              clearOutboxError(channelId);
              setAttachmentError(null);
              setPasteError(null);
            }}
            className="underline"
          >
            閉じる
          </button>
        </div>
      )}
      {channelAttachmentTasks.length > 0 && (
        <div aria-live="polite" className="mb-2 space-y-2 rounded bg-discord-sidebar px-3 py-2 text-xs text-discord-muted">
          {channelAttachmentTasks.map((task) => (
            <div key={task.id} className="space-y-1">
              <div className="flex items-center justify-between gap-3">
                <span className="min-w-0 truncate">
                  {task.fileName} — {attachmentTaskLabel(task.status)}
                </span>
                <div className="flex shrink-0 gap-2">
                  {(task.status === 'preparing' || task.status === 'uploading' || task.status === 'finalizing') && (
                    <button type="button" onClick={() => cancelUpload(task.id)} className="underline">取消</button>
                  )}
                  {(task.status === 'failed' || task.status === 'cancelled') && (
                    <button type="button" onClick={() => retryUpload(task.id)} disabled={!isOnline} className="underline disabled:opacity-50">
                      再開
                    </button>
                  )}
                  {(task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') && (
                    <button type="button" onClick={() => dismissUpload(task.id)} className="underline">閉じる</button>
                  )}
                </div>
              </div>
              <progress
                value={task.progress}
                max={100}
                aria-label={`${task.fileName} アップロード進捗 ${task.progress}%`}
                className={`h-1 w-full overflow-hidden rounded ${task.status === 'failed' ? 'accent-discord-red' : 'accent-discord-accent'}`}
              />
              {task.error && <p role="alert" className="text-discord-red">{task.error}</p>}
            </div>
          ))}
        </div>
      )}
      {channelOutboxItems.length > 0 && (
        <div aria-live="polite" className="mb-2 space-y-1 rounded bg-discord-sidebar px-3 py-2 text-xs text-discord-muted">
          {channelOutboxItems.map((item) => (
            <div key={item.id} className="flex items-center justify-between gap-3">
              <span>
                {item.status === 'sending' && '暗号化outboxから送信中…'}
                {item.status === 'queued' && (item.error || '未送信（接続復旧後に自動再送）')}
                {item.status === 'failed' && (item.error || '送信に失敗しました')}
              </span>
              {item.status !== 'sending' && (
                <button type="button" onClick={() => retry(item.id)} className="shrink-0 text-discord-text underline">
                  再試行
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      <form onSubmit={handleSubmit} className="relative">
        {selectedFiles.length > 0 && (
          <ul aria-label="送信する添付ファイル" className="mb-2 space-y-1 rounded bg-discord-sidebar px-3 py-2 text-xs text-discord-muted">
            {selectedFiles.map((file, index) => (
              <li key={`${file.name}:${file.size}:${file.lastModified}:${index}`} className="flex items-center justify-between gap-3">
                <span className="truncate">{file.name}（{formatFileSize(file.size)}）</span>
                <button
                  type="button"
                  onClick={() => setSelectedFiles((current) => current.filter((_, currentIndex) => currentIndex !== index))}
                  className="shrink-0 underline"
                >
                  削除
                </button>
              </li>
            ))}
          </ul>
        )}
        <textarea
          ref={textareaRef}
          id={`message-input-${channelId}`}
          value={content}
          onChange={(e) => {
            if (editTarget) setEditContent(e.target.value);
            else setDraft(channelId, e.target.value);
            handleTyping();
          }}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          placeholder={editTarget ? 'メッセージを編集' : 'メッセージを送信'}
          aria-label={editTarget ? 'メッセージを編集' : 'メッセージを送信'}
          className="w-full min-h-[44px] max-h-[200px] px-4 py-3 bg-discord-input rounded-lg text-discord-text placeholder-discord-muted outline-none resize-none focus:ring-1 focus:ring-discord-accent"
          rows={1}
          maxLength={MAX_MESSAGE_LENGTH}
        />
        <div className="mt-2 flex items-center justify-between gap-3 text-xs text-discord-muted">
          <div className="flex min-w-0 items-center gap-2">
            {!editTarget && (
              <>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={!isOnline || isSending}
                  className="rounded px-2 py-1 hover:bg-discord-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  ＋ 画像・ファイル（最大{ATTACHMENT_MAX_COUNT_PER_MESSAGE}件・各100MB）
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  disabled={!isOnline || isSending}
                  onChange={handleFilesSelected}
                  aria-label="送信する画像またはファイルを選択"
                  className="sr-only"
                  tabIndex={-1}
                />
                {!isOnline && <span role="status" className="truncate">オフライン中は本文のみ暗号化outboxへ保存できます</span>}
              </>
            )}
          </div>
          <button
            type="submit"
            disabled={isSending || (!content.trim() && selectedFiles.length === 0)}
            className="shrink-0 rounded bg-discord-accent px-4 py-2 font-medium text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isSending ? '送信中…' : editTarget ? '変更を保存' : selectedFiles.length > 0 ? '画像・ファイルを送信' : '送信'}
          </button>
        </div>
      </form>
    </div>
  );
}

function attachmentTaskLabel(status: string): string {
  if (status === 'queued') return '待機中';
  if (status === 'preparing') return '鍵と予約を準備中';
  if (status === 'uploading') return '暗号化アップロード中';
  if (status === 'finalizing') return '検証・確定中';
  if (status === 'completed') return '送信完了';
  if (status === 'cancelled') return '取消済み';
  return '送信失敗';
}

function formatFileSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / 1024 / 1024).toFixed(1)} MiB`;
}
