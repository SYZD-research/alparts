import { create } from 'zustand';
import {
  MAX_FILE_SIZE,
  type Attachment,
  type Message,
  type SignedAttachmentEnvelope,
} from '@alparts/shared';
import { api, ApiError, type AttachmentUploadReservation } from '../services/api';
import {
  ATTACHMENT_MAX_COUNT_PER_MESSAGE,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  attachmentChunkCount,
  attachmentCiphertextChunkSize,
  attachmentPlaintextChunkSize,
  encodeCanonicalBase64,
  encryptAttachmentChunk,
  normalizeAttachmentMimeType,
  prepareAttachmentFileKey,
  sealPreparedAttachmentFileKey,
  verifyAttachmentMetadata,
  wrapSealedAttachmentFileKey,
  clearAttachmentVerificationCache,
} from '../services/attachment-crypto.service';
import {
  assertAttachmentReservationContract,
  attachmentExpiryRecoveryPlan,
  cancelAttachmentReservationBestEffort,
  createAttachmentReservationWithRetry,
  withTransientAttachmentRetry,
} from '../services/attachment-transfer.service';
import {
  ensureChannelKey,
  getActiveDevice,
  getChannelKeyForVersion,
  signAttachmentEnvelope,
} from '../services/crypto.service';
import { useMessageStore } from './message.store';
import { t } from '../i18n';

export type AttachmentUploadStatus =
  | 'queued'
  | 'preparing'
  | 'uploading'
  | 'finalizing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface AttachmentUploadTask {
  id: string;
  channelId: string;
  messageId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  status: AttachmentUploadStatus;
  progress: number;
  uploadedChunks: number;
  totalChunks: number;
  error: string | null;
  /** Refused because the conversation's members changed: only sending the file again helps. */
  resendRequired?: boolean;
  attachmentId: string | null;
}

interface PreparedUpload {
  reservation: AttachmentUploadReservation;
  fileKey: CryptoKey;
  filenameEnc: string;
  noncePrefix: Uint8Array;
  wrappedKey: string;
  chunkCount: number;
  mimeType: string;
}

interface ReservationAttempt {
  idempotencyKey: string;
  channelKey: CryptoKey;
  fileKey: CryptoKey;
  filenameEnc: string;
  noncePrefix: Uint8Array;
  sealedFileKey: string;
  chunkCount: number;
  mimeType: string;
}

interface UploadRuntime {
  file: File;
  message: Message;
  prepared?: PreparedUpload;
  reservationAttempt?: ReservationAttempt;
  reservationIdempotencyKey: string;
  reservationUploadId?: string;
  controller?: AbortController;
  running: boolean;
  cancelled: boolean;
  expiryAutoRetries: number;
}

interface AttachmentState {
  tasks: Record<string, AttachmentUploadTask>;
  /**
   * Throws at once, registering nothing, when the files cannot be queued (for
   * example offline or at the local upload limit). Otherwise returns a promise
   * that settles when the queued uploads have run.
   */
  startUploads: (message: Message, files: File[]) => Promise<void>;
  retryUpload: (taskId: string) => void;
  resumeFailedUploads: () => void;
  cancelUpload: (taskId: string) => void;
  dismissUpload: (taskId: string) => void;
  clearChannel: (channelId: string) => void;
  reset: () => void;
}

const runtimes = new Map<string, UploadRuntime>();
const MAX_LOCAL_ATTACHMENT_RUNTIMES = 16;
const MAX_LOCAL_ATTACHMENT_TASK_HISTORY = 64;
let attachmentGeneration = 0;
let resuming = false;

function isMembershipRefusal(error: unknown): boolean {
  return error instanceof ApiError && error.status === 400 && error.reason === 'KEY_ROTATION_REQUIRED';
}

function taskErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (isMembershipRefusal(error)) {
      return t('この会話のメンバーが変わったため、ファイルを送信できませんでした。もう一度送信してください。');
    }
    if (error.status === 403) return t('このチャンネルで添付ファイルを送信する権限がありません');
    if (error.status === 413) return t('ストレージ容量またはファイルサイズの上限を超えました');
    if (error.status === 410 && error.code === 'UPLOAD_EXPIRED') return t('アップロードの有効期限が切れました。自動的にやり直します');
    if (error.status === 409) return t('アップロード状態が競合しました。一覧を再読み込みして確認してください');
    if (error.status === 429) return t('アップロードが混雑しています。しばらくして再試行してください');
  }
  return error instanceof Error && error.message ? error.message : t('添付ファイルを送信できませんでした');
}

function isOnline(): boolean {
  return typeof navigator === 'undefined' || navigator.onLine;
}

function updateTask(taskId: string, update: Partial<AttachmentUploadTask>): void {
  useAttachmentStore.setState((state) => {
    const current = state.tasks[taskId];
    if (!current) return state;
    return { tasks: { ...state.tasks, [taskId]: { ...current, ...update } } };
  });
}

function isCurrentRuntime(taskId: string, runtime: UploadRuntime, generation: number): boolean {
  return generation === attachmentGeneration
    && !runtime.cancelled
    && runtimes.get(taskId) === runtime;
}

async function prepareUpload(runtime: UploadRuntime, signal: AbortSignal): Promise<PreparedUpload> {
  const { file, message } = runtime;
  if (file.size > MAX_FILE_SIZE) throw new Error(t('添付ファイルは100MB以下にしてください'));
  const attempt = runtime.reservationAttempt || await createReservationAttempt(runtime);
  if (
    signal.aborted
    || runtime.cancelled
    || attempt.idempotencyKey !== runtime.reservationIdempotencyKey
  ) {
    throw new DOMException(t('操作はキャンセルされました'), 'AbortError');
  }
  runtime.reservationAttempt = attempt;
  const reservation = await createAttachmentReservationWithRetry({
    messageId: message.id,
    filenameEnc: attempt.filenameEnc,
    mimeType: attempt.mimeType,
    idempotencyKey: attempt.idempotencyKey,
  }, signal);
  if (reservation.uploadId !== attempt.idempotencyKey) {
    throw new Error(t('添付予約IDがclient idempotency keyと一致しません'));
  }
  runtime.reservationUploadId = reservation.uploadId;
  if (signal.aborted || runtime.cancelled) {
    void cancelAttachmentReservationBestEffort(reservation.uploadId);
    throw new DOMException(t('操作はキャンセルされました'), 'AbortError');
  }
  assertAttachmentReservationContract(reservation, file.size);
  const wrappedKey = await wrapSealedAttachmentFileKey(
    attempt.sealedFileKey,
    attempt.channelKey,
    message.id,
    attempt.idempotencyKey,
    reservation.uploadId,
  );
  if (signal.aborted || runtime.cancelled) {
    void cancelAttachmentReservationBestEffort(reservation.uploadId);
    throw new DOMException(t('操作はキャンセルされました'), 'AbortError');
  }
  const prepared: PreparedUpload = {
    reservation,
    fileKey: attempt.fileKey,
    filenameEnc: attempt.filenameEnc,
    noncePrefix: attempt.noncePrefix,
    wrappedKey,
    chunkCount: attempt.chunkCount,
    mimeType: attempt.mimeType,
  };
  runtime.prepared = prepared;
  runtime.reservationAttempt = undefined;
  return prepared;
}

async function createReservationAttempt(runtime: UploadRuntime): Promise<ReservationAttempt> {
  const { file, message } = runtime;
  const channelKey = await getChannelKeyForVersion(message.channelId, message.keyVersion);
  if (!channelKey) throw new Error(t('このチャンネルは現在ファイルを送信できません'));
  const preparedKey = await prepareAttachmentFileKey(file.name, message.id);
  try {
    if (preparedKey.filenameEnc.length > 8192) throw new Error(t('添付ファイル名が長すぎます'));
    return {
      idempotencyKey: runtime.reservationIdempotencyKey,
      channelKey,
      fileKey: preparedKey.fileKey,
      filenameEnc: preparedKey.filenameEnc,
      noncePrefix: preparedKey.noncePrefix,
      sealedFileKey: await sealPreparedAttachmentFileKey(
        preparedKey.rawFileKey,
        channelKey,
        message.id,
        runtime.reservationIdempotencyKey,
      ),
      chunkCount: attachmentChunkCount(file.size),
      mimeType: normalizeAttachmentMimeType(file.type),
    };
  } finally {
    preparedKey.rawFileKey.fill(0);
  }
}

async function recoverCompletedAttachment(runtime: UploadRuntime, prepared: PreparedUpload): Promise<Attachment | null> {
  await useMessageStore.getState().loadMessages(runtime.message.channelId);
  const base = (useMessageStore.getState().eventsByChannel[runtime.message.channelId] || [])
    .find((event) => event.id === runtime.message.id);
  return base?.attachments?.find((attachment) => (
    attachment.cryptoManifest?.uploadId === prepared.reservation.uploadId
  )) || null;
}

async function runUpload(taskId: string): Promise<void> {
  const runtime = runtimes.get(taskId);
  if (!runtime || runtime.running || runtime.cancelled) return;
  if (!isOnline()) {
    updateTask(taskId, { status: 'failed', error: t('オフラインです。接続復旧後に再開します') });
    return;
  }

  const generation = attachmentGeneration;
  runtime.running = true;
  const controller = new AbortController();
  runtime.controller = controller;
  let retryAfterExpiry = false;
  updateTask(taskId, {
    status: runtime.prepared ? 'uploading' : 'preparing',
    error: null,
  });

  try {
    const prepared = runtime.prepared || await prepareUpload(runtime, controller.signal);
    if (!isCurrentRuntime(taskId, runtime, generation)) return;

    const status = await withTransientAttachmentRetry(
      () => api.getAttachmentUploadStatus(prepared.reservation.uploadId, controller.signal),
      controller.signal,
    );
    if (status.messageId !== runtime.message.id || status.uploadId !== prepared.reservation.uploadId) {
      throw new Error(t('添付アップロードの再開情報が一致しません'));
    }
    const reportedIndexes = new Set(status.uploadedIndexes);
    if (
      reportedIndexes.size !== status.uploadedIndexes.length
      || status.chunks.length !== reportedIndexes.size
      || status.chunks.some((chunk) => (
        !reportedIndexes.has(chunk.index) || chunk.index < 0 || chunk.index >= prepared.chunkCount
      ))
    ) {
      throw new Error(t('添付アップロードのチャンク状態が不正です'));
    }
    const uploadedSizes = new Map(status.chunks.map((chunk) => [chunk.index, chunk.ciphertextSizeBytes]));
    let uploadedBytes = 0;
    let uploadedChunks = 0;
    for (let index = 0; index < prepared.chunkCount; index += 1) {
      if (uploadedSizes.get(index) === attachmentCiphertextChunkSize(runtime.file.size, index)) {
        uploadedBytes += attachmentPlaintextChunkSize(runtime.file.size, index);
        uploadedChunks += 1;
      }
    }
    updateTask(taskId, {
      status: 'uploading',
      uploadedChunks,
      progress: runtime.file.size === 0 ? (uploadedChunks ? 100 : 0) : Math.round((uploadedBytes / runtime.file.size) * 100),
    });

    for (let index = 0; index < prepared.chunkCount; index += 1) {
      const expectedCiphertextSize = attachmentCiphertextChunkSize(runtime.file.size, index);
      if (uploadedSizes.get(index) === expectedCiphertextSize) continue;
      if (controller.signal.aborted) throw new DOMException(t('操作はキャンセルされました'), 'AbortError');
      const start = index * ATTACHMENT_PLAINTEXT_CHUNK_BYTES;
      const end = Math.min(runtime.file.size, start + ATTACHMENT_PLAINTEXT_CHUNK_BYTES);
      const plaintext = await runtime.file.slice(start, end).arrayBuffer();
      let ciphertext: ArrayBuffer | null = null;
      try {
        ciphertext = await encryptAttachmentChunk(
          plaintext,
          prepared.fileKey,
          prepared.noncePrefix,
          prepared.reservation.uploadId,
          runtime.message.id,
          index,
          prepared.chunkCount,
          runtime.file.size,
        );
        if (ciphertext.byteLength !== expectedCiphertextSize) throw new Error(t('暗号化チャンクのサイズが不正です'));
        await withTransientAttachmentRetry(
          () => api.putAttachmentChunk(
            prepared.reservation.uploadId,
            index,
            ciphertext as ArrayBuffer,
            controller.signal,
          ),
          controller.signal,
        );
      } finally {
        new Uint8Array(plaintext).fill(0);
        if (ciphertext) new Uint8Array(ciphertext).fill(0);
      }

      uploadedBytes += attachmentPlaintextChunkSize(runtime.file.size, index);
      uploadedChunks += 1;
      updateTask(taskId, {
        uploadedChunks,
        progress: runtime.file.size === 0 ? 100 : Math.round((uploadedBytes / runtime.file.size) * 100),
      });
    }

    updateTask(taskId, { status: 'finalizing', progress: 100 });
    const noncePrefix = encodeCanonicalBase64(prepared.noncePrefix);
    const device = getActiveDevice();
    const signedEnvelope: SignedAttachmentEnvelope = {
      type: 'attachment',
      uploadId: prepared.reservation.uploadId,
      messageId: runtime.message.id,
      channelId: runtime.message.channelId,
      authorId: runtime.message.authorId,
      deviceId: device.deviceId,
      keyVersion: runtime.message.keyVersion,
      filenameEnc: prepared.filenameEnc,
      mimeType: prepared.mimeType,
      wrappedKey: prepared.wrappedKey,
      noncePrefix,
      plaintextSize: runtime.file.size,
      chunkCount: prepared.chunkCount,
      // The message's own signed key, checked against the signed request it was sent with.
      messageIdempotencyKey: runtime.message.idempotencyKey,
    };
    const signature = await signAttachmentEnvelope(signedEnvelope);
    const finalize = () => withTransientAttachmentRetry(
      () => api.finalizeAttachmentUpload(prepared.reservation.uploadId, {
        deviceId: device.deviceId,
        keyVersion: runtime.message.keyVersion,
        signature,
        chunkCount: prepared.chunkCount,
        wrappedKey: prepared.wrappedKey,
        cryptoManifest: {
          version: 1,
          algorithm: 'AES-256-GCM',
          nonceStrategy: 'prefix-counter-be32',
          noncePrefix,
          aadVersion: 1,
          plaintextSize: runtime.file.size,
        },
      }, controller.signal),
      controller.signal,
    );
    let attachment: Attachment;
    try {
      try {
        attachment = await finalize();
      } catch (error) {
        if (!isMembershipRefusal(error)) throw error;
        // A removal or a key refresh may be due first. Bring the channel up
        // to date once, then finalize again; a refusal after that stays.
        try {
          await ensureChannelKey(runtime.message.channelId, { purpose: 'write' });
        } catch {
          throw error;
        }
        if (!isCurrentRuntime(taskId, runtime, generation)) return;
        attachment = await finalize();
      }
    } catch (error) {
      if (error instanceof ApiError && error.code === 'UPLOAD_ALREADY_COMPLETED') {
        const recovered = await recoverCompletedAttachment(runtime, prepared);
        if (recovered) attachment = recovered;
        else throw error;
      } else {
        throw error;
      }
    }

    if (!isCurrentRuntime(taskId, runtime, generation)) return;
    await verifyAttachmentMetadata(runtime.message, attachment);
    if (!isCurrentRuntime(taskId, runtime, generation)) return;
    useMessageStore.getState().applyAttachment(runtime.message.channelId, attachment);
    updateTask(taskId, {
      status: 'completed',
      progress: 100,
      uploadedChunks: prepared.chunkCount,
      error: null,
      attachmentId: attachment.id,
    });
    runtimes.delete(taskId);
  } catch (error) {
    if (!isCurrentRuntime(taskId, runtime, generation)) return;
    if (
      error instanceof ApiError
      && error.code === 'UPLOAD_ALREADY_COMPLETED'
      && runtime.prepared
    ) {
      const recovered = await recoverCompletedAttachment(runtime, runtime.prepared).catch(() => null);
      if (recovered && isCurrentRuntime(taskId, runtime, generation)) {
        try {
          await verifyAttachmentMetadata(runtime.message, recovered);
          useMessageStore.getState().applyAttachment(runtime.message.channelId, recovered);
          updateTask(taskId, {
            status: 'completed',
            progress: 100,
            uploadedChunks: runtime.prepared.chunkCount,
            error: null,
            attachmentId: recovered.id,
          });
          runtimes.delete(taskId);
          return;
        } catch (verificationError) {
          updateTask(taskId, { status: 'failed', error: taskErrorMessage(verificationError) });
          return;
        }
      }
    }
    const expiryPlan = attachmentExpiryRecoveryPlan(error, Boolean(
      runtime.prepared || runtime.reservationUploadId || runtime.reservationAttempt,
    ), runtime.expiryAutoRetries);
    if (expiryPlan.rotateMaterial) {
      // A new upload id changes chunk AAD. Rotate file key, nonce prefix and
      // reservation idempotency together to prevent AES-GCM nonce reuse.
      renewReservationAttempt(runtime);
      runtime.expiryAutoRetries += 1;
      retryAfterExpiry = expiryPlan.retryAutomatically;
    }
    updateTask(taskId, controller.signal.aborted
      ? { status: 'cancelled', error: t('アップロードをキャンセルしました') }
      : retryAfterExpiry
        ? { status: 'queued', error: null, progress: 0, uploadedChunks: 0 }
        : { status: 'failed', error: taskErrorMessage(error), resendRequired: isMembershipRefusal(error) });
  } finally {
    runtime.running = false;
    runtime.controller = undefined;
    if (retryAfterExpiry && isCurrentRuntime(taskId, runtime, generation)) await runUpload(taskId);
  }
}

export const useAttachmentStore = create<AttachmentState>((set, get) => ({
  tasks: {},

  startUploads: (message, files) => {
    if (files.length === 0) return Promise.resolve();
    if (files.length > ATTACHMENT_MAX_COUNT_PER_MESSAGE) {
      throw new Error(t('1件のメッセージに添付できるファイルは{count}件までです', { count: ATTACHMENT_MAX_COUNT_PER_MESSAGE }));
    }
    if (!isOnline()) throw new Error(t('添付ファイルはオンライン時のみ送信できます'));
    if (runtimes.size + files.length > MAX_LOCAL_ATTACHMENT_RUNTIMES) {
      throw new Error(t('端末上の添付アップロード上限に達しました'));
    }
    set((state) => ({
      tasks: pruneTerminalTaskHistory(state.tasks, files.length),
    }));

    const taskIds = files.map((file) => {
      const id = crypto.randomUUID();
      const totalChunks = attachmentChunkCount(file.size);
      runtimes.set(id, {
        file,
        message,
        running: false,
        cancelled: false,
        expiryAutoRetries: 0,
        reservationIdempotencyKey: crypto.randomUUID(),
      });
      set((state) => ({
        tasks: {
          ...state.tasks,
          [id]: {
            id,
            channelId: message.channelId,
            messageId: message.id,
            fileName: file.name,
            mimeType: normalizeAttachmentMimeType(file.type),
            sizeBytes: file.size,
            status: 'queued',
            progress: 0,
            uploadedChunks: 0,
            totalChunks,
            error: null,
            attachmentId: null,
          },
        },
      }));
      return id;
    });

    // Sequential processing bounds plaintext/ciphertext memory to one 5MiB
    // chunk pair even when a message contains several files.
    return (async () => {
      for (const taskId of taskIds) await runUpload(taskId);
    })();
  },

  retryUpload: (taskId) => {
    const runtime = runtimes.get(taskId);
    if (!runtime || get().tasks[taskId]?.resendRequired) return;
    runtime.cancelled = false;
    runtime.expiryAutoRetries = 0;
    void runUpload(taskId);
  },

  resumeFailedUploads: () => {
    if (resuming || !isOnline()) return;
    resuming = true;
    void (async () => {
      try {
        // An upload refused because the members changed since its message
        // never succeeds again; only sending the file anew does.
        const taskIds = Object.values(get().tasks)
          .filter((task) => task.status === 'failed' && !task.resendRequired && runtimes.has(task.id))
          .map((task) => task.id);
        for (const taskId of taskIds) await runUpload(taskId);
      } finally {
        resuming = false;
      }
    })();
  },

  cancelUpload: (taskId) => {
    const runtime = runtimes.get(taskId);
    if (!runtime) return;
    const finalizing = get().tasks[taskId]?.status === 'finalizing';
    const prepared = runtime.prepared;
    runtime.cancelled = true;
    if (runtime.controller) runtime.controller.abort();
    runtimes.delete(taskId);
    if (!finalizing || !prepared) {
      cancelKnownReservation(runtime);
      updateTask(taskId, { status: 'cancelled', error: t('アップロードをキャンセルしました') });
      return;
    }
    // The server may already have accepted the file. Report what it decided
    // instead of assuming the cancellation won.
    void settleFinalizingCancellation(taskId, runtime, prepared);
  },

  dismissUpload: (taskId) => {
    const runtime = runtimes.get(taskId);
    runtime?.controller?.abort();
    if (runtime) cancelKnownReservation(runtime);
    runtimes.delete(taskId);
    set((state) => {
      const tasks = { ...state.tasks };
      delete tasks[taskId];
      return { tasks };
    });
  },

  clearChannel: (channelId) => {
    const removedTaskIds = new Set(
      Object.values(get().tasks)
        .filter((task) => task.channelId === channelId)
        .map((task) => task.id),
    );
    for (const [taskId, runtime] of runtimes) {
      if (runtime.message.channelId !== channelId) continue;
      runtime.cancelled = true;
      runtime.controller?.abort();
      cancelRuntimeReservation(runtime);
      runtimes.delete(taskId);
      removedTaskIds.add(taskId);
    }
    if (removedTaskIds.size === 0) return;
    set((state) => ({
      tasks: Object.fromEntries(Object.entries(state.tasks)
        .filter(([taskId]) => !removedTaskIds.has(taskId))),
    }));
  },

  reset: () => {
    attachmentGeneration += 1;
    resuming = false;
    for (const runtime of runtimes.values()) runtime.controller?.abort();
    runtimes.clear();
    clearAttachmentVerificationCache();
    set({ tasks: {} });
  },
}));

async function settleFinalizingCancellation(taskId: string, runtime: UploadRuntime, prepared: PreparedUpload): Promise<void> {
  const generation = attachmentGeneration;
  let cancelled = false;
  try {
    await api.cancelAttachmentUpload(prepared.reservation.uploadId);
    cancelled = true;
  } catch {
    // Already completed, or unknown: look for the file below.
  }
  let attachment: Attachment | null = null;
  if (!cancelled) {
    try {
      attachment = await recoverCompletedAttachment(runtime, prepared);
      if (attachment) await verifyAttachmentMetadata(runtime.message, attachment);
    } catch {
      attachment = null;
    }
  }
  if (generation !== attachmentGeneration) return;
  if (!attachment) {
    updateTask(taskId, { status: 'cancelled', error: t('アップロードをキャンセルしました') });
    return;
  }
  useMessageStore.getState().applyAttachment(runtime.message.channelId, attachment);
  updateTask(taskId, {
    status: 'completed',
    progress: 100,
    uploadedChunks: prepared.chunkCount,
    error: null,
    attachmentId: attachment.id,
  });
}

/** What the viewer can do with an upload in each state. */
export function attachmentTaskActions(
  status: AttachmentUploadStatus,
  resendRequired = false,
): { cancel: boolean; resume: boolean; dismiss: boolean } {
  return {
    cancel: status === 'preparing' || status === 'uploading' || status === 'finalizing',
    // A cancelled upload has released its file; only a failed one can resume,
    // unless the conversation's members changed since its message was sent.
    resume: status === 'failed' && !resendRequired,
    dismiss: status === 'completed' || status === 'failed' || status === 'cancelled',
  };
}

function pruneTerminalTaskHistory(
  tasks: Record<string, AttachmentUploadTask>,
  reserve: number,
): Record<string, AttachmentUploadTask> {
  const entries = Object.entries(tasks);
  const active = entries.filter(([, task]) => task.status !== 'completed' && task.status !== 'cancelled');
  const terminal = entries.filter(([, task]) => task.status === 'completed' || task.status === 'cancelled');
  const terminalSlots = Math.max(0, MAX_LOCAL_ATTACHMENT_TASK_HISTORY - reserve - active.length);
  return Object.fromEntries([
    ...active,
    ...(terminalSlots === 0 ? [] : terminal.slice(-terminalSlots)),
  ]);
}

function cancelKnownReservation(runtime: UploadRuntime): void {
  // Local UI cancellation is immediate; server cleanup is deliberately
  // best-effort and never reuses the cancelled idempotency attempt.
  cancelRuntimeReservation(runtime);
  renewReservationAttempt(runtime);
}

function cancelRuntimeReservation(runtime: UploadRuntime): void {
  const uploadId = runtime.prepared?.reservation.uploadId
    || runtime.reservationUploadId
    || runtime.reservationIdempotencyKey;
  void cancelAttachmentReservationBestEffort(uploadId);
}

function renewReservationAttempt(runtime: UploadRuntime): void {
  runtime.prepared = undefined;
  runtime.reservationAttempt = undefined;
  runtime.reservationUploadId = undefined;
  runtime.reservationIdempotencyKey = crypto.randomUUID();
}
