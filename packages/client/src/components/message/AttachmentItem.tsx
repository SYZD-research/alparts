import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { Attachment, Message } from '@alparts/shared';
import {
  decryptAttachmentFilename,
  isDangerousAttachmentFilename,
  type AttachmentMessage,
} from '../../services/attachment-crypto.service';
import { getMessageCryptoVerificationState } from '../../stores/message-projector';
import {
  downloadAttachment,
  loadAttachmentImagePreview,
  type AttachmentDownloadProgress,
} from '../../services/attachment-transfer.service';
import {
  ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES,
  canPreviewImage,
  isPreviewableImageMimeType,
} from '../../services/attachment-preview';

interface Props {
  attachment: Attachment;
  message: AttachmentMessage;
}

const EMPTY_PROGRESS: AttachmentDownloadProgress = {
  completedBytes: 0,
  totalBytes: 0,
  completedChunks: 0,
  totalChunks: 0,
};

export function AttachmentItem({ attachment, message }: Props) {
  const [filename, setFilename] = useState<string | null>(null);
  const [metadataVerified, setMetadataVerified] = useState(false);
  const [filenameError, setFilenameError] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [downloadState, setDownloadState] = useState<'idle' | 'downloading' | 'saved' | 'error'>('idle');
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [progress, setProgress] = useState(EMPTY_PROGRESS);
  const [previewState, setPreviewState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [previewProgress, setPreviewProgress] = useState(EMPTY_PROGRESS);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewAttempt, setPreviewAttempt] = useState(0);
  const [expanded, setExpanded] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);
  const previewControllerRef = useRef<AbortController | null>(null);
  const attachmentIdentity = attachmentSecurityIdentity(attachment);
  // A file opens only once the message it belongs to has been verified.
  const messageVerification = getMessageCryptoVerificationState(message as Message);

  useEffect(() => {
    let disposed = false;
    setFilename(null);
    setMetadataVerified(false);
    setFilenameError(null);
    setAcknowledged(false);
    setExpanded(false);
    if (messageVerification === false) setFilenameError('ファイル名を確認できません');
    if (messageVerification === true) {
      void decryptAttachmentFilename(message, attachment).then((decrypted) => {
        if (!disposed) {
          setMetadataVerified(true);
          setFilename(decrypted);
        }
      }).catch(() => {
        if (!disposed) setFilenameError('ファイル名を確認できません');
      });
    }
    return () => {
      disposed = true;
      controllerRef.current?.abort();
      previewControllerRef.current?.abort();
    };
  }, [attachmentIdentity, message.authorId, message.channelId, message.id, message.keyVersion, message.idempotencyKey, messageVerification]);

  const dangerousFilename = useMemo(
    () => Boolean(filename && isDangerousAttachmentFilename(filename)),
    [filename],
  );
  const dangerous = metadataVerified && (attachment.dangerousMime || dangerousFilename);
  const previewEligible = Boolean(
    metadataVerified
    && filename
    && !dangerous
    && canPreviewImage(attachment.mimeType, attachment.cryptoManifest.plaintextSize),
  );
  const percentage = progress.totalBytes > 0
    ? Math.min(100, Math.round((progress.completedBytes / progress.totalBytes) * 100))
    : progress.completedChunks > 0 ? 100 : 0;
  const previewPercentage = previewProgress.totalBytes > 0
    ? Math.min(100, Math.round((previewProgress.completedBytes / previewProgress.totalBytes) * 100))
    : previewProgress.completedChunks > 0 ? 100 : 0;

  useEffect(() => {
    previewControllerRef.current?.abort();
    setPreviewUrl(null);
    setPreviewError(null);
    if (!previewEligible) {
      setPreviewState('idle');
      return;
    }

    const controller = new AbortController();
    previewControllerRef.current = controller;
    setPreviewState('loading');
    setPreviewProgress({
      ...EMPTY_PROGRESS,
      totalBytes: attachment.cryptoManifest.plaintextSize,
      totalChunks: attachment.chunkCount,
    });
    void loadAttachmentImagePreview(message, attachment, controller.signal, setPreviewProgress)
      .then((blob) => createDecodableImageUrl(blob, controller.signal))
      .then((url) => {
        if (controller.signal.aborted) {
          URL.revokeObjectURL(url);
          return;
        }
        setPreviewUrl(url);
        setPreviewState('ready');
      })
      .catch(() => {
        if (controller.signal.aborted) return;
        setPreviewState('error');
        setPreviewError('画像を表示できません。ファイルとして保存できます');
      })
      .finally(() => {
        if (previewControllerRef.current === controller) previewControllerRef.current = null;
      });
    return () => controller.abort();
  }, [
    attachmentIdentity,
    message.authorId,
    message.channelId,
    message.id,
    message.keyVersion,
    previewAttempt,
    previewEligible,
  ]);

  useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  const markPreviewUnrenderable = () => {
    setExpanded(false);
    setPreviewUrl(null);
    setPreviewState('error');
    setPreviewError('画像を表示できません。ファイルとして保存できます');
  };

  const imagePreviewPending = isPreviewableImageMimeType(attachment.mimeType)
    && attachment.cryptoManifest.plaintextSize <= ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES
    && !attachment.dangerousMime
    && !filenameError
    && (!metadataVerified || (previewEligible && (previewState === 'idle' || previewState === 'loading')));

  if (imagePreviewPending) {
    return (
      <div className="mt-2 max-w-xl" aria-live="polite">
        <progress value={previewPercentage} max={100} aria-label={`画像を準備中 ${previewPercentage}%`} className="h-1.5 w-full overflow-hidden rounded accent-discord-accent" />
      </div>
    );
  }

  if (previewUrl && previewState === 'ready') {
    return (
      <>
        <button
          type="button"
          aria-label="画像を拡大表示"
          aria-haspopup="dialog"
          aria-expanded={expanded}
          onClick={() => setExpanded(true)}
          className="mt-2 block max-w-full cursor-zoom-in rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-discord-accent"
        >
          <img
            src={previewUrl}
            alt={filename || '添付画像'}
            className="max-h-80 max-w-full rounded object-contain"
            onError={markPreviewUnrenderable}
          />
        </button>
        <ExpandedImage
          open={expanded}
          src={previewUrl}
          alt={filename || '添付画像'}
          onClose={() => setExpanded(false)}
          onError={markPreviewUnrenderable}
        />
      </>
    );
  }

  const startDownload = async () => {
    if (!filename || filenameError || downloadState === 'downloading' || (dangerous && !acknowledged)) return;
    const controller = new AbortController();
    controllerRef.current = controller;
    setDownloadState('downloading');
    setDownloadError(null);
    setProgress({ ...EMPTY_PROGRESS, totalBytes: attachment.plaintextSizeBytes || 0, totalChunks: attachment.chunkCount });
    try {
      await downloadAttachment(message, attachment, filename, controller.signal, setProgress, dangerous);
      setDownloadState('saved');
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        setDownloadState('idle');
      } else {
        setDownloadState('error');
        setDownloadError('ファイルを保存できませんでした。時間をおいて再試行してください');
      }
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  };

  return (
      <section
        aria-label="添付ファイル"
        className="mt-2 max-w-xl rounded border border-discord-hover bg-discord-sidebar/70 p-3 text-sm"
      >
        <div>
          <div className="min-w-0">
            <p className="truncate font-medium text-discord-text">
              {filename || (filenameError ? 'ファイル名を確認できない添付ファイル' : 'ファイル名を確認中…')}
            </p>
            <p className="text-xs text-discord-muted">
              {metadataVerified
                ? formatBytes(attachment.plaintextSizeBytes)
                : filenameError ? 'ファイル情報を確認できません' : 'ファイル情報を確認中…'}
            </p>
          </div>
        </div>

      {dangerous && (
        <div role="alert" className="mt-2 rounded border border-discord-yellow/50 bg-discord-yellow/10 p-2 text-xs text-discord-yellow">
          <p className="font-semibold">安全でない可能性があるファイルです</p>
          <p className="mt-1">
            信頼できる相手から届いた場合のみ保存してください。
          </p>
          <label className="mt-2 flex cursor-pointer items-start gap-2 text-discord-text">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
              className="mt-0.5"
            />
            警告を確認し、ファイルとして保存します
          </label>
        </div>
      )}

      {filenameError && <p role="alert" className="mt-2 text-xs text-discord-red">{filenameError}</p>}
      {previewError && (
        <div role="alert" className="mt-2 flex items-center gap-2 text-xs text-discord-red">
          <span>{previewError}</span>
          <button type="button" onClick={() => setPreviewAttempt((value) => value + 1)} className="shrink-0 underline">再試行</button>
        </div>
      )}
      {metadataVerified
        && isPreviewableImageMimeType(attachment.mimeType)
        && attachment.cryptoManifest.plaintextSize > ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES
        && (
          <p className="mt-2 text-xs text-discord-muted">
            25MBを超える画像は、ファイルとして保存してください。
          </p>
        )}
      {downloadError && <p role="alert" className="mt-2 text-xs text-discord-red">{downloadError}</p>}
      {downloadState === 'downloading' && (
        <div className="mt-2" aria-live="polite">
          <progress
            value={percentage}
            max={100}
            aria-label={`添付ファイル保存進捗 ${percentage}%`}
            className="h-1.5 w-full overflow-hidden rounded accent-discord-accent"
          />
          <p className="mt-1 text-xs text-discord-muted">
            保存中 {percentage}%
          </p>
        </div>
      )}
      {downloadState === 'saved' && (
        <p role="status" className="mt-2 text-xs text-discord-green">保存しました</p>
      )}

      <div className="mt-3 flex gap-2">
        <button
          type="button"
          onClick={() => void startDownload()}
          disabled={!filename || Boolean(filenameError) || downloadState === 'downloading' || (dangerous && !acknowledged)}
          className="rounded bg-discord-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-discord-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {downloadState === 'saved' ? 'もう一度保存' : 'ファイルを保存'}
        </button>
        {downloadState === 'downloading' && (
          <button
            type="button"
            onClick={() => controllerRef.current?.abort()}
            className="rounded bg-discord-hover px-3 py-1.5 text-xs text-discord-text hover:bg-discord-red"
          >
            キャンセル
          </button>
        )}
      </div>
      </section>
  );
}

function ExpandedImage({
  open,
  src,
  alt,
  onClose,
  onError,
}: {
  open: boolean;
  src: string;
  alt: string;
  onClose: () => void;
  onError: () => void;
}) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const bodyAlreadyLocked = document.body.classList.contains('overflow-hidden');
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
      } else if (event.key === 'Tab') {
        event.preventDefault();
        closeButtonRef.current?.focus();
      }
    };
    document.body.classList.add('overflow-hidden');
    document.addEventListener('keydown', handleKeyDown);
    requestAnimationFrame(() => closeButtonRef.current?.focus());
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (!bodyAlreadyLocked) document.body.classList.remove('overflow-hidden');
      previous?.focus();
    };
  }, [open]);

  if (!open || typeof document === 'undefined') return null;
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label="画像を拡大表示"
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/85 p-4"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <img
        src={src}
        alt={alt}
        className="max-h-[calc(100vh-2rem)] max-w-[calc(100vw-2rem)] object-contain"
        onError={onError}
      />
      <button
        ref={closeButtonRef}
        type="button"
        onClick={onClose}
        aria-label="閉じる"
        className="absolute right-4 top-4 flex h-10 w-10 items-center justify-center rounded-full bg-black/70 text-2xl text-white hover:bg-black focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
      >
        ×
      </button>
    </div>,
    document.body,
  );
}

function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return 'サイズ不明';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

/** Avoid restarting a decrypt/download merely because a store projection made a new object. */
function attachmentSecurityIdentity(attachment: Attachment): string {
  return JSON.stringify([
    attachment.id,
    attachment.messageId,
    attachment.channelId,
    attachment.keyVersion,
    attachment.deviceId,
    attachment.signature,
    attachment.filenameEnc,
    attachment.mimeType,
    attachment.dangerousMime,
    attachment.downloadPolicy,
    attachment.sizeBytes,
    attachment.ciphertextSizeBytes,
    attachment.plaintextSizeBytes,
    attachment.chunkCount,
    attachment.wrappedKey,
    attachment.contentNonce,
    attachment.cryptoManifest,
  ]);
}

/** Preload the local Blob URL so a broken-image placeholder is never committed to the UI. */
function createDecodableImageUrl(blob: Blob, signal: AbortSignal): Promise<string> {
  if (signal.aborted) return Promise.reject(new DOMException('操作はキャンセルされました', 'AbortError'));
  if (blob.size <= 0) return Promise.reject(new Error('画像データが空です'));
  const url = URL.createObjectURL(blob);
  return new Promise<string>((resolve, reject) => {
    const probe = new Image();
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      probe.onload = null;
      probe.onerror = null;
      if (error) {
        URL.revokeObjectURL(url);
        reject(error);
      } else {
        resolve(url);
      }
    };
    const onAbort = () => finish(new DOMException('操作はキャンセルされました', 'AbortError'));
    probe.onload = () => finish(
      probe.naturalWidth > 0 && probe.naturalHeight > 0
        ? undefined
        : new Error('画像の大きさを確認できませんでした'),
    );
    probe.onerror = () => finish(new Error('画像を表示できません'));
    signal.addEventListener('abort', onAbort, { once: true });
    probe.decoding = 'async';
    probe.src = url;
  });
}
