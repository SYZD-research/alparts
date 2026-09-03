import { useState, useRef, useCallback, useEffect, useLayoutEffect, useMemo } from 'react';
import { useMessageStore } from '../../stores/message.store';
import { useDraftStore } from '../../stores/draft.store';
import { useOutboxStore } from '../../stores/outbox.store';
import { useAttachmentStore } from '../../stores/attachment.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { getSocket } from '../../services/socket';
import { MAX_FILE_SIZE, MAX_MESSAGE_LENGTH } from '@alparts/shared';
import { ATTACHMENT_MAX_COUNT_PER_MESSAGE } from '../../services/attachment-crypto.service';
import { Dialog } from '../ui/Dialog';
import {
  insertPastedText,
  previewLargePaste,
  type LargePastePreview,
} from '../../stores/paste-preview-model';
import {
  ATTACHMENT_IMAGE_PREVIEW_HEADER_BYTES,
  canPreviewImage,
  matchesPreviewImageSignature,
} from '../../services/attachment-preview';
import {
  applyMentionCompletion,
  filterMentionMembers,
  findActiveMentionQuery,
  type ActiveMentionQuery,
  type MentionMember,
} from '../../services/mention-model';

interface Props {
  channelId: string;
  sendDisabled?: boolean;
}

interface PendingPaste {
  channelId: string;
  editMessageId: string | null;
  text: string;
  start: number;
  end: number;
  preview: LargePastePreview;
}

export function MessageInput({ channelId, sendDisabled = false }: Props) {
  const [editContent, setEditContent] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);
  const [pendingPaste, setPendingPaste] = useState<PendingPaste | null>(null);
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [isDraggingFiles, setIsDraggingFiles] = useState(false);
  const [activeMention, setActiveMention] = useState<ActiveMentionQuery | null>(null);
  const [activeMentionIndex, setActiveMentionIndex] = useState(0);
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
  const workspaceMembers = useWorkspaceStore((state) => state.members);
  const typingTimeout = useRef<ReturnType<typeof setTimeout>>();
  const lastTypingSent = useRef<number>(0);
  const dragDepth = useRef(0);
  const content = editTarget ? editContent : draft;
  const mentionMembers = useMemo<MentionMember[]>(() => workspaceMembers.map((member) => ({
    userId: member.userId,
    displayName: member.user.displayName,
  })), [workspaceMembers]);
  const mentionCandidates = useMemo(() => filterMentionMembers(
    mentionMembers,
    activeMention?.query || '',
  ), [activeMention?.query, mentionMembers]);
  const showMentionPopup = Boolean(
    activeMention && (activeMention.query.length === 0 || mentionCandidates.length > 0),
  );
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
    setActiveMention(null);
    setActiveMentionIndex(0);
    dragDepth.current = 0;
    setIsDraggingFiles(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, [channelId]);

  useEffect(() => {
    if (!editTarget) return;
    setActiveMention(null);
    setActiveMentionIndex(0);
    dragDepth.current = 0;
    setIsDraggingFiles(false);
  }, [editTarget]);

  useLayoutEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = '0px';
    const nextHeight = Math.max(44, Math.min(textarea.scrollHeight, 200));
    textarea.style.height = `${nextHeight}px`;
    textarea.style.overflowY = textarea.scrollHeight > 200 ? 'auto' : 'hidden';
  }, [channelId, content]);

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
    if ((!content.trim() && selectedFiles.length === 0) || isSending || sendDisabled) return;
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
        void startUploads(message, files).catch(() => {
          setAttachmentError('ファイルを送信できませんでした。もう一度お試しください');
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
    } catch {
      if (selectedFiles.length > 0) {
        setAttachmentError('ファイルを送信できませんでした。もう一度お試しください');
      }
    } finally {
      setIsSending(false);
    }
  };

  const addSelectedFiles = (files: File[]) => {
    setAttachmentError(null);
    if (editTarget) {
      setAttachmentError('編集中のメッセージにはファイルを追加できません');
      return;
    }
    if (!isOnline) {
      setAttachmentError('添付ファイルはオンライン時のみ追加できます');
      return;
    }
    const seen = new Set(selectedFiles.map(fileIdentity));
    const uniqueFiles = files.filter((file) => {
      const identity = fileIdentity(file);
      if (seen.has(identity)) return false;
      seen.add(identity);
      return true;
    });
    const nextFiles = [...selectedFiles, ...uniqueFiles];
    if (nextFiles.length > ATTACHMENT_MAX_COUNT_PER_MESSAGE) {
      setAttachmentError(`添付ファイルは1メッセージ${ATTACHMENT_MAX_COUNT_PER_MESSAGE}件までです`);
      return;
    }
    const oversized = nextFiles.find((file) => file.size > MAX_FILE_SIZE);
    if (oversized) {
      setAttachmentError(`${oversized.name} は100MBを超えています`);
      return;
    }
    setSelectedFiles(nextFiles);
  };

  const handleFilesSelected = (event: React.ChangeEvent<HTMLInputElement>) => {
    addSelectedFiles(Array.from(event.target.files || []));
    event.target.value = '';
  };

  const hasDraggedFiles = (event: React.DragEvent) => Array.from(event.dataTransfer.types).includes('Files');

  const handleDragEnter = (event: React.DragEvent<HTMLFormElement>) => {
    if (!hasDraggedFiles(event)) return;
    event.preventDefault();
    if (editTarget) return;
    dragDepth.current += 1;
    setIsDraggingFiles(true);
  };

  const handleDragOver = (event: React.DragEvent<HTMLFormElement>) => {
    if (!hasDraggedFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = editTarget || sendDisabled || !isOnline ? 'none' : 'copy';
  };

  const handleDragLeave = (event: React.DragEvent<HTMLFormElement>) => {
    if (dragDepth.current === 0) return;
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setIsDraggingFiles(false);
  };

  const handleDrop = (event: React.DragEvent<HTMLFormElement>) => {
    if (!hasDraggedFiles(event)) return;
    event.preventDefault();
    dragDepth.current = 0;
    setIsDraggingFiles(false);
    if (sendDisabled) {
      setAttachmentError('準備が完了してからファイルを追加してください');
      return;
    }
    addSelectedFiles(Array.from(event.dataTransfer.files));
  };

  const completeMention = (member: MentionMember) => {
    if (!activeMention) return;
    const duplicateDisplayName = mentionMembers.filter((candidate) => (
      candidate.displayName.trim().normalize('NFKC').toLocaleLowerCase()
      === member.displayName.trim().normalize('NFKC').toLocaleLowerCase()
    )).length > 1;
    const completion = applyMentionCompletion(content, activeMention, member, duplicateDisplayName);
    if (completion.content.length > MAX_MESSAGE_LENGTH) return;
    if (editTarget) setEditContent(completion.content);
    else setDraft(channelId, completion.content);
    setActiveMention(null);
    setActiveMentionIndex(0);
    handleTyping();
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(completion.caret, completion.caret);
    });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (showMentionPopup && mentionCandidates.length > 0) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const direction = e.key === 'ArrowDown' ? 1 : -1;
        setActiveMentionIndex((current) => (
          (current + direction + mentionCandidates.length) % mentionCandidates.length
        ));
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        completeMention(mentionCandidates[Math.min(activeMentionIndex, mentionCandidates.length - 1)]);
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        setActiveMention(null);
        return;
      }
    }
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
    setActiveMention(null);
    setActiveMentionIndex(0);
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
        description="内容を確認してから入力欄へ追加できます。"
        size="md"
      >
        {pendingPaste && (
          <div className="space-y-4">
            <p className="text-sm text-discord-muted">
              {pendingPaste.preview.byteCount.toLocaleString('ja-JP')}文字分・{pendingPaste.preview.lineCount.toLocaleString('ja-JP')}行
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
          <span>
            {attachmentError
              || pasteError
              || (draftError ? '下書きを保存できませんでした。もう一度お試しください' : null)
              || (outboxError ? 'メッセージを送信できませんでした。もう一度お試しください' : null)}
          </span>
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
              {task.error && <p role="alert" className="text-discord-red">ファイルを送信できませんでした。再試行してください</p>}
            </div>
          ))}
        </div>
      )}
      {channelOutboxItems.length > 0 && (
        <div aria-live="polite" className="mb-2 space-y-1 rounded bg-discord-sidebar px-3 py-2 text-xs text-discord-muted">
          {channelOutboxItems.map((item) => (
            <div key={item.id} className="flex items-center justify-between gap-3">
              <span>
                {item.status === 'sending' && '送信中…'}
                {item.status === 'queued' && '未送信（接続後に自動送信）'}
                {item.status === 'failed' && '送信できませんでした'}
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
      <form
        onSubmit={handleSubmit}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className="relative"
      >
        {isDraggingFiles && (
          <div className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center rounded-lg border-2 border-dashed border-discord-accent bg-discord-bg/95 text-sm font-semibold text-white">
            ここに画像・ファイルをドロップ
          </div>
        )}
        {selectedFiles.length > 0 && (
          <ul aria-label="送信する添付ファイル" className="mb-2 flex flex-wrap gap-2 rounded bg-discord-sidebar p-2 text-xs text-discord-muted">
            {selectedFiles.map((file, index) => (
              <PendingFilePreview
                key={`${fileIdentity(file)}:${index}`}
                file={file}
                onRemove={() => setSelectedFiles((current) => current.filter((_, currentIndex) => currentIndex !== index))}
              />
            ))}
          </ul>
        )}
        <div className="relative">
          {showMentionPopup && (
            <div
              id={`mention-list-${channelId}`}
              className="absolute bottom-full left-0 right-0 z-30 mb-2 max-h-64 overflow-hidden rounded-lg border border-discord-hover bg-discord-sidebar shadow-2xl"
              aria-label="メンション候補"
            >
              <p className="border-b border-discord-hover px-3 py-2 text-[11px] font-bold uppercase tracking-wide text-discord-muted">
                メンションするメンバー
              </p>
              {mentionCandidates.length > 0 ? (
                <ul role="listbox" className="max-h-52 overflow-y-auto p-1">
                  {mentionCandidates.map((candidate, index) => {
                    const workspaceMember = workspaceMembers.find((member) => member.userId === candidate.userId);
                    const selected = index === Math.min(activeMentionIndex, mentionCandidates.length - 1);
                    return (
                      <li key={candidate.userId} role="presentation">
                        <button
                          id={`mention-option-${candidate.userId}`}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          onMouseDown={(event) => event.preventDefault()}
                          onClick={() => completeMention(candidate)}
                          onMouseEnter={() => setActiveMentionIndex(index)}
                          className={`flex w-full items-center gap-2 rounded px-2 py-2 text-left text-sm ${
                            selected ? 'bg-discord-accent text-white' : 'text-discord-text hover:bg-discord-hover'
                          }`}
                        >
                          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-discord-bg font-bold text-white">
                            {candidate.displayName.slice(0, 1).toUpperCase()}
                          </span>
                          <span className="min-w-0 flex-1 truncate font-medium">@{candidate.displayName}</span>
                          {workspaceMember?.user.status && (
                            <span className="shrink-0 text-[11px] opacity-70">
                              {workspaceMember.user.status === 'online' ? 'オンライン' : workspaceMember.user.status === 'offline' ? 'オフライン' : '退席中'}
                            </span>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <p className="px-3 py-3 text-sm text-discord-muted">候補を読み込めませんでした</p>
              )}
            </div>
          )}
          <textarea
            ref={textareaRef}
            id={`message-input-${channelId}`}
            value={content}
            onChange={(event) => {
              const nextContent = event.target.value;
              if (editTarget) setEditContent(nextContent);
              else setDraft(channelId, nextContent);
              setActiveMention(findActiveMentionQuery(nextContent, event.target.selectionStart));
              setActiveMentionIndex(0);
              handleTyping();
            }}
            onSelect={(event) => {
              setActiveMention(findActiveMentionQuery(content, event.currentTarget.selectionStart));
              setActiveMentionIndex(0);
            }}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            placeholder={editTarget ? 'メッセージを編集' : 'メッセージを送信'}
            aria-label={editTarget ? 'メッセージを編集' : 'メッセージを送信'}
            aria-autocomplete="list"
            aria-expanded={showMentionPopup}
            aria-controls={showMentionPopup ? `mention-list-${channelId}` : undefined}
            aria-activedescendant={showMentionPopup && mentionCandidates.length > 0
              ? `mention-option-${mentionCandidates[Math.min(activeMentionIndex, mentionCandidates.length - 1)].userId}`
              : undefined}
            className="block min-h-[44px] max-h-[200px] w-full resize-none rounded-lg bg-discord-input px-4 py-3 text-discord-text outline-none placeholder-discord-muted focus:ring-1 focus:ring-discord-accent"
            rows={1}
            maxLength={MAX_MESSAGE_LENGTH}
          />
        </div>
        <div className="mt-2 flex items-center justify-between gap-3 text-xs text-discord-muted">
          <div className="flex min-w-0 items-center gap-2">
            {!editTarget && (
              <>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={!isOnline || isSending || sendDisabled}
                  className="rounded px-2 py-1 hover:bg-discord-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  ＋ 画像・ファイル（最大{ATTACHMENT_MAX_COUNT_PER_MESSAGE}件・各100MB）
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  disabled={!isOnline || isSending || sendDisabled}
                  onChange={handleFilesSelected}
                  aria-label="送信する画像またはファイルを選択"
                  className="sr-only"
                  tabIndex={-1}
                />
                {!isOnline && <span role="status" className="truncate">オフライン中は本文のみ保存され、接続復旧後に自動送信されます</span>}
              </>
            )}
          </div>
          <button
            type="submit"
            disabled={isSending || sendDisabled || (!content.trim() && selectedFiles.length === 0)}
            className="shrink-0 rounded bg-discord-accent px-4 py-2 font-medium text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isSending ? '送信中…' : sendDisabled ? '準備中…' : editTarget ? '変更を保存' : selectedFiles.length > 0 ? '画像・ファイルを送信' : '送信'}
          </button>
        </div>
      </form>
    </div>
  );
}

function PendingFilePreview({ file, onRemove }: { file: File; onRemove: () => void }) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewUnavailable, setPreviewUnavailable] = useState(false);

  useEffect(() => {
    let disposed = false;
    setPreviewUrl(null);
    setPreviewUnavailable(false);
    if (!canPreviewImage(file.type, file.size)) {
      return;
    }
    void file.slice(0, ATTACHMENT_IMAGE_PREVIEW_HEADER_BYTES).arrayBuffer()
      .then((header) => {
        if (disposed) return;
        if (!matchesPreviewImageSignature(file.type, new Uint8Array(header))) {
          setPreviewUnavailable(true);
          return;
        }
        setPreviewUrl(URL.createObjectURL(file));
      })
      .catch(() => {
        if (!disposed) setPreviewUnavailable(true);
      });
    return () => { disposed = true; };
  }, [file]);

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  return (
    <li className="relative w-36 overflow-hidden rounded border border-discord-hover bg-discord-bg/60">
      {previewUrl ? (
        <img
          src={previewUrl}
          alt={`${file.name} のプレビュー`}
          className="h-24 w-full bg-discord-input object-contain"
          onError={() => {
            setPreviewUrl(null);
            setPreviewUnavailable(true);
          }}
        />
      ) : (
        <div className="flex h-24 flex-col items-center justify-center px-3 text-center" aria-hidden="true">
          <span className="text-2xl">📄</span>
          {previewUnavailable && <span className="mt-1 text-[10px] text-discord-muted">画像プレビュー不可</span>}
        </div>
      )}
      <div className="px-2 py-1.5">
        <p className="truncate text-discord-text" title={file.name}>{file.name}</p>
        <p>{formatFileSize(file.size)}</p>
      </div>
      <button
        type="button"
        onClick={onRemove}
        className="absolute right-1 top-1 flex h-6 w-6 items-center justify-center rounded-full bg-discord-bg/90 text-sm text-white hover:bg-discord-red"
        aria-label={`${file.name}を添付から削除`}
        title="添付から削除"
      >
        ×
      </button>
    </li>
  );
}

function fileIdentity(file: File): string {
  return `${file.name}:${file.size}:${file.lastModified}:${file.type}`;
}

function attachmentTaskLabel(status: string): string {
  if (status === 'queued') return '待機中';
  if (status === 'preparing') return '準備中';
  if (status === 'uploading') return 'アップロード中';
  if (status === 'finalizing') return '確認中';
  if (status === 'completed') return '送信完了';
  if (status === 'cancelled') return '取消済み';
  return '送信失敗';
}

function formatFileSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / 1024 / 1024).toFixed(1)} MiB`;
}
