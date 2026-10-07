import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Attachment, Message } from '@alparts/shared';

const mocks = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(
      message: string,
      readonly status: number,
      readonly code: string | null = null,
      readonly reason: string | null = null,
    ) {
      super(message);
    }
  }
  const messageState = {
    eventsByChannel: {} as Record<string, Message[]>,
    loadMessages: vi.fn(async () => undefined),
    applyAttachment: vi.fn(),
  };
  return {
    ApiError,
    messageState,
    ensureChannelKey: vi.fn(async () => ({ key: {} as CryptoKey, version: 2 })),
    api: {
      getAttachmentUploadStatus: vi.fn(),
      putAttachmentChunk: vi.fn(async () => undefined),
      finalizeAttachmentUpload: vi.fn(),
      cancelAttachmentUpload: vi.fn(),
    },
  };
});

vi.mock('../services/api', () => ({ api: mocks.api, ApiError: mocks.ApiError }));
vi.mock('./message.store', () => ({ useMessageStore: { getState: () => mocks.messageState } }));
vi.mock('../services/crypto.service', () => ({
  ensureChannelKey: mocks.ensureChannelKey,
  getActiveDevice: () => ({ deviceId: 'device', userId: 'author' }),
  getChannelKeyForVersion: vi.fn(async () => ({}) as CryptoKey),
  signAttachmentEnvelope: vi.fn(async () => 'signature'),
}));
vi.mock('../services/attachment-crypto.service', async (importOriginal) => {
  const original = await importOriginal<typeof import('../services/attachment-crypto.service')>();
  return {
    ...original,
    prepareAttachmentFileKey: vi.fn(async () => ({
      fileKey: {} as CryptoKey,
      rawFileKey: new Uint8Array(32),
      filenameEnc: 'name',
      noncePrefix: new Uint8Array(8),
    })),
    sealPreparedAttachmentFileKey: vi.fn(async () => 'sealed'),
    wrapSealedAttachmentFileKey: vi.fn(async () => 'wrapped'),
    encryptAttachmentChunk: vi.fn(async (_plain: ArrayBuffer, _key: unknown, _nonce: unknown, _upload: unknown, _message: unknown, index: number, _count: number, size: number) => (
      new ArrayBuffer(original.attachmentCiphertextChunkSize(size, index))
    )),
    verifyAttachmentMetadata: vi.fn(async () => undefined),
    clearAttachmentVerificationCache: vi.fn(),
  };
});
vi.mock('../services/attachment-transfer.service', async (importOriginal) => {
  const original = await importOriginal<typeof import('../services/attachment-transfer.service')>();
  return {
    ...original,
    createAttachmentReservationWithRetry: vi.fn(async (input: { idempotencyKey: string }) => ({ uploadId: input.idempotencyKey })),
    assertAttachmentReservationContract: vi.fn(),
    withTransientAttachmentRetry: (operation: () => Promise<unknown>) => operation(),
    cancelAttachmentReservationBestEffort: vi.fn(async () => true),
  };
});

import { attachmentTaskActions, useAttachmentStore } from './attachment.store';

const channelId = 'channel';
const message = { id: 'message', channelId, authorId: 'author', keyVersion: 1, type: 'message' } as Message;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function until(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100 && !condition(); attempt += 1) await new Promise((resolve) => setTimeout(resolve, 0));
  expect(condition()).toBe(true);
}

const onlyTask = () => Object.values(useAttachmentStore.getState().tasks)[0]!;

beforeEach(() => {
  vi.stubGlobal('navigator', { onLine: true });
  useAttachmentStore.getState().reset();
  mocks.messageState.eventsByChannel = {};
  vi.clearAllMocks();
  mocks.api.getAttachmentUploadStatus.mockImplementation(async (uploadId: string) => ({
    messageId: message.id, uploadId, uploadedIndexes: [], chunks: [],
  }));
});

describe('starting uploads (SQ-06)', () => {
  it('refuses at once, registering nothing, so the caller can keep the files', () => {
    vi.stubGlobal('navigator', { onLine: false });
    expect(() => useAttachmentStore.getState().startUploads(message, [new File(['x'], 'a.txt')])).toThrow();
    expect(useAttachmentStore.getState().tasks).toEqual({});
  });
});

describe('cancelling while the upload is being confirmed (SQ-24)', () => {
  async function startToFinalizing() {
    const finalize = deferred<Attachment>();
    mocks.api.finalizeAttachmentUpload.mockImplementation((_uploadId: string, _body: unknown, signal: AbortSignal) => {
      signal.addEventListener('abort', () => finalize.reject(new DOMException('aborted', 'AbortError')));
      return finalize.promise;
    });
    const running = useAttachmentStore.getState().startUploads(message, [new File(['hello'], 'a.txt')]);
    await until(() => mocks.api.finalizeAttachmentUpload.mock.calls.length === 1);
    expect(onlyTask().status).toBe('finalizing');
    // Wrapped so awaiting this helper does not wait for the upload itself.
    return { running };
  }

  it('shows the file as sent when the server had already accepted it', async () => {
    const { running } = await startToFinalizing();
    const uploadId = mocks.api.finalizeAttachmentUpload.mock.calls[0]![0] as string;
    const attachment = { id: 'attachment', messageId: message.id, cryptoManifest: { uploadId } } as unknown as Attachment;
    mocks.api.cancelAttachmentUpload.mockRejectedValue(new mocks.ApiError('done', 409, 'UPLOAD_ALREADY_COMPLETED'));
    mocks.messageState.loadMessages.mockImplementation(async () => {
      mocks.messageState.eventsByChannel[channelId] = [{ ...message, attachments: [attachment] }];
    });

    useAttachmentStore.getState().cancelUpload(onlyTask().id);
    await running;
    await until(() => onlyTask().status !== 'finalizing');

    expect(onlyTask().status).toBe('completed');
    expect(mocks.messageState.applyAttachment).toHaveBeenCalledWith(channelId, attachment);
  });

  it('shows the upload as cancelled when the cancellation came first', async () => {
    const { running } = await startToFinalizing();
    mocks.api.cancelAttachmentUpload.mockResolvedValue({ uploadId: 'x', cancelled: true, alreadyAbsent: false });

    useAttachmentStore.getState().cancelUpload(onlyTask().id);
    await running;
    await until(() => onlyTask().status !== 'finalizing');

    expect(onlyTask().status).toBe('cancelled');
    expect(mocks.messageState.applyAttachment).not.toHaveBeenCalled();
  });

  it('offers no resume for a cancelled upload, whose file is no longer kept', () => {
    expect(attachmentTaskActions('cancelled').resume).toBe(false);
    expect(attachmentTaskActions('failed').resume).toBe(true);
  });
});

describe('finalizing after the members of the channel changed', () => {
  const refused = () => new mocks.ApiError('refused', 400, 'VALIDATION', 'KEY_ROTATION_REQUIRED');

  it('brings the channel up to date once and finalizes again', async () => {
    const attachment = { id: 'attachment', messageId: message.id } as unknown as Attachment;
    mocks.api.finalizeAttachmentUpload.mockRejectedValueOnce(refused()).mockResolvedValueOnce(attachment);
    await useAttachmentStore.getState().startUploads(message, [new File(['hello'], 'a.txt')]);
    await until(() => onlyTask().status === 'completed');
    expect(mocks.ensureChannelKey).toHaveBeenCalledWith(channelId, { purpose: 'write' });
    expect(mocks.api.finalizeAttachmentUpload).toHaveBeenCalledTimes(2);
  });

  it('fails with a plain message when the server still refuses', async () => {
    mocks.api.finalizeAttachmentUpload.mockRejectedValue(refused());
    await useAttachmentStore.getState().startUploads(message, [new File(['hello'], 'a.txt')]);
    await until(() => onlyTask().status === 'failed');
    expect(mocks.api.finalizeAttachmentUpload).toHaveBeenCalledTimes(2);
    expect(onlyTask().error).toBe('この会話のメンバーが変わったため、ファイルを送信できませんでした。もう一度送信してください。');
    expect(onlyTask().resendRequired).toBe(true);
    expect(attachmentTaskActions('failed', true).resume).toBe(false);
  });
});
