import { MAX_FILE_SIZE, type Attachment, type Message } from '@alparts/shared';
import {
  api,
  ApiError,
  type AttachmentUploadCreateInput,
  type AttachmentUploadReservation,
} from './api';
import {
  ATTACHMENT_CHUNK_AAD_FORMAT,
  ATTACHMENT_FALLBACK_BLOB_LIMIT_BYTES,
  ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_NONCE_PREFIX_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  buildSignedAttachmentEnvelope,
  decryptAttachmentChunk,
  sanitizeAttachmentFilename,
  unwrapAttachmentFileKey,
  validateAttachmentManifest,
} from './attachment-crypto.service';
import {
  boundedBackoffDelayMs,
  MAX_RETRY_ATTEMPTS,
} from './fixed-request-retry';
import {
  ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES,
  canPreviewImage,
  matchesPreviewImageSignature,
} from './attachment-preview';
import { getDesktopBridge } from './desktop.service';

export interface AttachmentDownloadProgress {
  completedBytes: number;
  totalBytes: number;
  completedChunks: number;
  totalChunks: number;
}

interface WritableFileLike {
  write(data: BufferSource | Blob | string): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

interface FileHandleLike {
  createWritable(): Promise<WritableFileLike>;
}

interface SavePickerOptionsLike {
  suggestedName?: string;
}

type SaveFilePicker = (options?: SavePickerOptionsLike) => Promise<FileHandleLike>;

export function isTransientAttachmentError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === 'AbortError') return false;
  if (error instanceof ApiError) {
    return error.status === 408
      || error.status === 425
      || error.status === 429
      || (error.status >= 500 && error.status <= 599);
  }
  return error instanceof TypeError;
}

export async function withTransientAttachmentRetry<T>(
  operation: () => Promise<T>,
  signal: AbortSignal,
  attempts = 4,
  baseDelayMs = 250,
): Promise<T> {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > MAX_RETRY_ATTEMPTS) {
    throw new Error('Retry attempts are outside the supported range');
  }
  boundedBackoffDelayMs(0, baseDelayMs);
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    throwIfAborted(signal);
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!isTransientAttachmentError(error) || attempt === attempts - 1) throw error;
      await abortableDelay(boundedBackoffDelayMs(attempt, baseDelayMs), signal);
    }
  }
  throw lastError;
}

export async function createAttachmentReservationWithRetry(
  input: AttachmentUploadCreateInput,
  signal: AbortSignal,
  operation: (
    fixedInput: AttachmentUploadCreateInput,
    fixedSignal: AbortSignal,
  ) => Promise<AttachmentUploadReservation> = (fixedInput, fixedSignal) => (
    api.createAttachmentUpload(fixedInput, fixedSignal)
  ),
  attempts = 4,
  baseDelayMs = 250,
): Promise<AttachmentUploadReservation> {
  return withTransientAttachmentRetry(() => operation(input, signal), signal, attempts, baseDelayMs);
}

/** Cancellation must never turn a local cancel/dismiss action into a failure. */
export async function cancelAttachmentReservationBestEffort(
  uploadId: string | null | undefined,
  operation: (id: string) => Promise<unknown> = (id) => api.cancelAttachmentUpload(id),
): Promise<boolean> {
  if (!uploadId) return false;
  try {
    await operation(uploadId);
    return true;
  } catch {
    return false;
  }
}

export function isExpiredKnownAttachmentReservation(error: unknown, hasKnownReservation: boolean): boolean {
  return hasKnownReservation
    && error instanceof ApiError
    && error.status === 410
    && error.code === 'UPLOAD_EXPIRED';
}

export function attachmentExpiryRecoveryPlan(
  error: unknown,
  hasKnownReservation: boolean,
  automaticRetriesUsed: number,
): { rotateMaterial: boolean; retryAutomatically: boolean } {
  const rotateMaterial = isExpiredKnownAttachmentReservation(error, hasKnownReservation);
  return {
    rotateMaterial,
    retryAutomatically: rotateMaterial && automaticRetriesUsed < 1,
  };
}

export function assertAttachmentReservationContract(
  reservation: AttachmentUploadReservation,
  plaintextSize: number,
): void {
  if (
    reservation.chunkPlaintextBytes !== ATTACHMENT_PLAINTEXT_CHUNK_BYTES
    || reservation.chunkCiphertextBytes !== ATTACHMENT_PLAINTEXT_CHUNK_BYTES + ATTACHMENT_GCM_TAG_BYTES
    || reservation.authenticationTagBytes !== ATTACHMENT_GCM_TAG_BYTES
    || reservation.maxPlaintextBytes !== MAX_FILE_SIZE
    || reservation.maxChunkCount !== Math.ceil(MAX_FILE_SIZE / ATTACHMENT_PLAINTEXT_CHUNK_BYTES)
    || reservation.crypto.version !== 1
    || reservation.crypto.algorithm !== 'AES-256-GCM'
    || reservation.crypto.nonceStrategy !== 'prefix-counter-be32'
    || reservation.crypto.noncePrefixBytes !== ATTACHMENT_NONCE_PREFIX_BYTES
    || reservation.crypto.aadVersion !== 1
    || reservation.crypto.aadFormat !== ATTACHMENT_CHUNK_AAD_FORMAT
    || plaintextSize > reservation.maxPlaintextBytes
  ) {
    throw new Error('サーバーとのファイル形式の取り決めが一致しません。最新版で再読み込みしてください');
  }
}

/**
 * Authenticates and decrypts a bounded raster image for an inline preview.
 * Active formats such as SVG are never accepted, and the returned Blob uses
 * the signed, normalized MIME type rather than sniffing untrusted content.
 */
export async function loadAttachmentImagePreview(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
  signal: AbortSignal,
  onProgress: (progress: AttachmentDownloadProgress) => void,
): Promise<Blob> {
  buildSignedAttachmentEnvelope(message, attachment);
  const manifest = validateAttachmentManifest(attachment, message.id);
  if (!canPreviewImage(attachment.mimeType, manifest.plaintextSize)) {
    throw new Error(
      manifest.plaintextSize > ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES
        ? '画像が大きいためプレビューできません。ファイルとして保存してください'
        : 'この画像形式は安全なプレビューに対応していません',
    );
  }

  const chunks: ArrayBuffer[] = [];
  try {
    const fileKey = await unwrapAttachmentFileKey(message, attachment);
    let completedBytes = 0;
    onProgress({
      completedBytes,
      totalBytes: manifest.plaintextSize,
      completedChunks: 0,
      totalChunks: manifest.chunkCount,
    });

    for (let index = 0; index < manifest.chunkCount; index += 1) {
      throwIfAborted(signal);
      const ciphertext = await withTransientAttachmentRetry(
        () => api.getAttachmentChunk(attachment.id, index, signal),
        signal,
      );
      throwIfAborted(signal);
      const plaintext = new Uint8Array(await decryptAttachmentChunk(ciphertext, fileKey, manifest, index));
      try {
        if (index === 0 && !matchesPreviewImageSignature(attachment.mimeType, plaintext)) {
          throw new Error('添付データが指定された画像形式と一致しないため、プレビューを停止しました');
        }
        const copy = new Uint8Array(plaintext.byteLength);
        copy.set(plaintext);
        chunks.push(copy.buffer);
        completedBytes += plaintext.byteLength;
        onProgress({
          completedBytes,
          totalBytes: manifest.plaintextSize,
          completedChunks: index + 1,
          totalChunks: manifest.chunkCount,
        });
      } finally {
        plaintext.fill(0);
      }
    }

    const blob = new Blob(chunks, { type: attachment.mimeType });
    for (const chunk of chunks) new Uint8Array(chunk).fill(0);
    return blob;
  } catch (error) {
    for (const chunk of chunks) new Uint8Array(chunk).fill(0);
    throw error;
  }
}

export async function downloadAttachment(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
  filename: string,
  signal: AbortSignal,
  onProgress: (progress: AttachmentDownloadProgress) => void,
  dangerous = false,
): Promise<'desktop' | 'filesystem' | 'browser'> {
  // Reject missing/mismatched signed fields synchronously before offering a
  // save location. Cryptographic signature verification happens in unwrap.
  buildSignedAttachmentEnvelope(message, attachment);
  const manifest = validateAttachmentManifest(attachment, message.id);
  const safeFilename = sanitizeAttachmentFilename(filename);
  const desktopFiles = getDesktopBridge()?.files;
  const picker = getSaveFilePicker();
  // Call the picker before the first await so the browser still considers this
  // operation part of the user's click activation.
  const desktopTokenPromise = desktopFiles
    ? desktopFiles.beginSave(safeFilename, manifest.plaintextSize, dangerous)
    : null;
  const handlePromise = !desktopFiles && picker ? picker({ suggestedName: safeFilename }) : null;
  let desktopToken: string | null = null;
  let writable: WritableFileLike | null = null;
  const fallbackChunks: ArrayBuffer[] = [];

  try {
    if (desktopTokenPromise) {
      desktopToken = await desktopTokenPromise;
      if (!desktopToken) throw new DOMException('操作はキャンセルされました', 'AbortError');
    } else if (handlePromise) {
      const handle = await handlePromise;
      writable = await handle.createWritable();
    } else if (manifest.plaintextSize > ATTACHMENT_FALLBACK_BLOB_LIMIT_BYTES) {
      throw new Error('このブラウザーでは100MBを超える添付を安全に保存できません');
    }

    const fileKey = await unwrapAttachmentFileKey(message, attachment);
    let completedBytes = 0;
    onProgress({
      completedBytes,
      totalBytes: manifest.plaintextSize,
      completedChunks: 0,
      totalChunks: manifest.chunkCount,
    });

    for (let index = 0; index < manifest.chunkCount; index += 1) {
      throwIfAborted(signal);
      const ciphertext = await withTransientAttachmentRetry(
        () => api.getAttachmentChunk(attachment.id, index, signal),
        signal,
      );
      throwIfAborted(signal);
      const plaintext = new Uint8Array(await decryptAttachmentChunk(ciphertext, fileKey, manifest, index));
      try {
        if (desktopFiles && desktopToken) {
          await desktopFiles.writeSave(desktopToken, plaintext.buffer);
        } else if (writable) {
          await writable.write(plaintext);
        } else {
          // Blob construction copies each part. Keeping only 5MiB pieces avoids
          // ever reading or concatenating the whole plaintext file ourselves.
          const copy = new Uint8Array(plaintext.byteLength);
          copy.set(plaintext);
          fallbackChunks.push(copy.buffer);
        }
        completedBytes += plaintext.byteLength;
        onProgress({
          completedBytes,
          totalBytes: manifest.plaintextSize,
          completedChunks: index + 1,
          totalChunks: manifest.chunkCount,
        });
      } finally {
        plaintext.fill(0);
      }
    }

    if (desktopFiles && desktopToken) {
      await desktopFiles.finishSave(desktopToken);
      desktopToken = null;
      return 'desktop';
    }

    if (writable) {
      await writable.close();
      writable = null;
      return 'filesystem';
    }

    // Always use octet-stream and a download-only anchor. No attachment bytes
    // are ever placed in img/object/embed/iframe or parsed as active content.
    const blob = new Blob(fallbackChunks, { type: 'application/octet-stream' });
    for (const chunk of fallbackChunks) new Uint8Array(chunk).fill(0);
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = safeFilename;
      anchor.rel = 'noopener';
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 0);
    }
    return 'browser';
  } catch (error) {
    if (desktopFiles && desktopToken) await desktopFiles.cancelSave(desktopToken).catch(() => undefined);
    if (writable) await writable.abort(error).catch(() => undefined);
    for (const chunk of fallbackChunks) new Uint8Array(chunk).fill(0);
    throw error;
  }
}

function getSaveFilePicker(): SaveFilePicker | null {
  if (typeof window === 'undefined') return null;
  const candidate = (window as Window & { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;
  return typeof candidate === 'function' ? candidate.bind(window) : null;
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException('操作はキャンセルされました', 'AbortError');
}

async function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('操作はキャンセルされました', 'AbortError'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
