import type { Message } from '@alparts/shared';

/** A message that was sent while its files could not be queued yet. */
export interface HeldAttachments {
  message: Message;
  files: File[];
}

export type AttachmentSendResult =
  | { status: 'started'; message: Message; uploads: Promise<void> }
  | { status: 'held'; message: Message; held: HeldAttachments };

/**
 * Send the message once, then queue its files. When the files cannot be
 * queued they stay bound to the message already sent, and retrying with the
 * returned `held` queues them for it again instead of sending the text twice.
 */
export async function sendWithAttachments(
  held: HeldAttachments | null,
  files: File[],
  sendMessage: () => Promise<Message>,
  startUploads: (message: Message, files: File[]) => Promise<void>,
): Promise<AttachmentSendResult> {
  const message = held?.message ?? await sendMessage();
  try {
    return { status: 'started', message, uploads: startUploads(message, files) };
  } catch {
    return { status: 'held', message, held: { message, files } };
  }
}
