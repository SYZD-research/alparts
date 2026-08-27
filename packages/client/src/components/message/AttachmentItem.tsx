import { useEffect, useMemo, useRef, useState } from 'react';
import type { Attachment, Message } from '@alparts/shared';
import {
  ATTACHMENT_FALLBACK_BLOB_LIMIT_BYTES,
  decryptAttachmentFilename,
  isDangerousAttachmentFilename,
} from '../../services/attachment-crypto.service';
import { downloadAttachment, type AttachmentDownloadProgress } from '../../services/attachment-transfer.service';

interface Props {
  attachment: Attachment;
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>;
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
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    let disposed = false;
    setFilename(null);
    setMetadataVerified(false);
    setFilenameError(null);
    setAcknowledged(false);
    void decryptAttachmentFilename(message, attachment).then((decrypted) => {
      if (!disposed) {
        setMetadataVerified(true);
        setFilename(decrypted);
      }
    }).catch(() => {
      if (!disposed) setFilenameError('ファイル名を安全に復号・検証できません');
    });
    return () => {
      disposed = true;
      controllerRef.current?.abort();
    };
  }, [attachment, message.authorId, message.channelId, message.id, message.keyVersion]);

  const dangerousFilename = useMemo(
    () => Boolean(filename && isDangerousAttachmentFilename(filename)),
    [filename],
  );
  const dangerous = metadataVerified && (attachment.dangerousMime || dangerousFilename);
  const percentage = progress.totalBytes > 0
    ? Math.min(100, Math.round((progress.completedBytes / progress.totalBytes) * 100))
    : progress.completedChunks > 0 ? 100 : 0;

  const startDownload = async () => {
    if (!filename || filenameError || downloadState === 'downloading' || (dangerous && !acknowledged)) return;
    const controller = new AbortController();
    controllerRef.current = controller;
    setDownloadState('downloading');
    setDownloadError(null);
    setProgress({ ...EMPTY_PROGRESS, totalBytes: attachment.plaintextSizeBytes || 0, totalChunks: attachment.chunkCount });
    try {
      await downloadAttachment(message, attachment, filename, controller.signal, setProgress);
      setDownloadState('saved');
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        setDownloadState('idle');
      } else {
        setDownloadState('error');
        setDownloadError(error instanceof Error ? error.message : '添付ファイルを保存できませんでした');
      }
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  };

  return (
    <section
      aria-label="暗号化された添付ファイル"
      className="mt-2 max-w-xl rounded border border-discord-hover bg-discord-sidebar/70 p-3 text-sm"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-medium text-discord-text">
            {filename || (filenameError ? '復号できない添付ファイル' : 'ファイル名を復号中…')}
          </p>
          <p className="text-xs text-discord-muted">
            {metadataVerified
              ? `${formatBytes(attachment.plaintextSizeBytes)} ・ ${attachment.mimeType}`
              : filenameError ? 'sender署名を検証できません' : 'sender署名を検証中…'}
          </p>
        </div>
        <span className="shrink-0 rounded bg-discord-hover px-2 py-0.5 text-[11px] text-discord-muted">
          {metadataVerified ? '署名検証済み E2EE' : '未検証'}
        </span>
      </div>

      {dangerous && (
        <div role="alert" className="mt-2 rounded border border-discord-yellow/50 bg-discord-yellow/10 p-2 text-xs text-discord-yellow">
          <p className="font-semibold">危険な可能性がある形式です</p>
          <p className="mt-1">
            MIMEまたは拡張子が、実行可能・active content・macro・archive形式に該当します。
            E2EEのためサーバー検査はなく、ブラウザーからOSの隔離属性も保証できません。信頼できる場合だけ保存してください。
          </p>
          <label className="mt-2 flex cursor-pointer items-start gap-2 text-discord-text">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
              className="mt-0.5"
            />
            警告を確認し、インライン表示せずファイルとして保存します
          </label>
        </div>
      )}

      <p className="mt-2 text-[11px] text-discord-muted">
        内容は表示・実行せず、5MiBずつ認証復号して保存します。File System Access非対応ブラウザーでは最大
        {Math.round(ATTACHMENT_FALLBACK_BLOB_LIMIT_BYTES / 1024 / 1024)}MBをメモリ上のBlob経由で保存します。
      </p>

      {filenameError && <p role="alert" className="mt-2 text-xs text-discord-red">{filenameError}</p>}
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
            復号・保存中 {percentage}%（{progress.completedChunks}/{progress.totalChunks}チャンク）
          </p>
        </div>
      )}
      {downloadState === 'saved' && (
        <p role="status" className="mt-2 text-xs text-discord-green">保存処理を完了しました</p>
      )}

      <div className="mt-3 flex gap-2">
        <button
          type="button"
          onClick={() => void startDownload()}
          disabled={!filename || Boolean(filenameError) || downloadState === 'downloading' || (dangerous && !acknowledged)}
          className="rounded bg-discord-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-discord-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {downloadState === 'saved' ? 'もう一度保存' : '復号して保存'}
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

function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return 'サイズ不明';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}
