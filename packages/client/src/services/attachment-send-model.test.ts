import { describe, expect, it, vi } from 'vitest';
import type { Message } from '@alparts/shared';
import { sendWithAttachments } from './attachment-send-model';

const message = { id: 'base', channelId: 'channel' } as Message;
const file = new File(['x'], 'a.txt');

describe('sending a message with files when the upload cannot start (SQ-06)', () => {
  it('keeps the files with the sent message and retries without sending the text again', async () => {
    const sendMessage = vi.fn(async () => message);
    const startUploads = vi.fn<(message: Message, files: File[]) => Promise<void>>()
      .mockImplementationOnce(() => { throw new Error('端末上の添付アップロード上限に達しました'); })
      .mockImplementationOnce(() => Promise.resolve());

    const first = await sendWithAttachments(null, [file], sendMessage, startUploads);
    expect(first.status).toBe('held');
    if (first.status !== 'held') return;
    expect(first.held).toEqual({ message, files: [file] });

    const retried = await sendWithAttachments(first.held, first.held.files, sendMessage, startUploads);
    expect(retried.status).toBe('started');
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(startUploads).toHaveBeenLastCalledWith(message, [file]);
  });
});
