import { isEpochRosterCurrent } from './key.service.js';
import { randomUUID } from 'node:crypto';
import type { Readable } from 'node:stream';
import { and, asc, eq, gt, inArray, isNotNull, isNull, lte, sql } from 'drizzle-orm';
import {
  ATTACHMENT_NONCE_PREFIX_BYTES,
  MAX_FILE_SIZE,
  Permissions,
  type SignedAttachmentEnvelope,
} from '@alparts/shared';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import {
  attachments,
  attachmentUploadChunks,
  attachmentUploads,
  channelKeyEpochRecipients,
  channelKeyEpochs,
  channels,
  devices,
  messages,
} from '../db/schema.js';
import {
  assertAuditWriteAvailable,
  auditedTransaction,
  auditGuardedTransaction,
} from '../middleware/audit.js';
import { verifyAttachmentEnvelopeSignature } from '../security/message.js';
import { signedIdempotencyKey } from './message-idempotency.js';
import { acquireDownloadLease } from '../security/download-limits.js';
import {
  MAX_PENDING_UPLOADS_PER_USER,
  MAX_PENDING_UPLOADS_PER_WORKSPACE,
} from '../security/limits.js';
import {
  getChannelAuthorizationFromStore,
  isVisibleChannelAuthorization,
  lockWorkspaceForAuthorization,
} from './authorization.service.js';
import {
  ATTACHMENT_CIPHERTEXT_CHUNK_BYTES,
  ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  ATTACHMENT_UPLOAD_TTL_MS,
  MAX_ATTACHMENT_CHUNKS,
  MAX_ATTACHMENTS_PER_MESSAGE,
  assertValidChunkIndex,
  assertValidFinalChunkCount,
  assertValidManifest,
  attachmentChunkAadFormat,
  attachmentChunkStorageKey,
  isDangerousAttachmentMime,
  validateFinalChunkLayout,
  type AttachmentCryptoManifestInput,
} from './attachment-contract.js';
import { hasRevokedEpochRecipient } from './key-epoch-state.js';
import {
  createObjectStorageDeadline,
  deleteStoredUpload,
  ensureObjectStorageBucket,
  getStoredObject,
  isObjectStorageTimeout,
  putStoredObject,
  reconcileStoredUpload,
  removeStoredObjectBestEffort,
  statStoredObject,
} from './object-storage.js';

export {
  ATTACHMENT_CIPHERTEXT_CHUNK_BYTES,
  ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_ATTACHMENT_CHUNKS,
  MAX_ATTACHMENTS_PER_MESSAGE,
  assertValidManifest,
  attachmentChunkAad,
  attachmentChunkAadFormat,
  attachmentChunkStorageKey,
  isDangerousAttachmentMime,
  validateFinalChunkLayout,
  type AttachmentCryptoManifestInput,
} from './attachment-contract.js';

interface StoredAttachmentCryptoManifest extends AttachmentCryptoManifestInput {
  chunkPlaintextBytes: number;
  authenticationTagBytes: number;
  chunkCount: number;
  uploadId: string;
  messageId: string;
  aadFormat: string;
}

interface UploadContext {
  upload: typeof attachmentUploads.$inferSelect;
  message: typeof messages.$inferSelect;
  channel: typeof channels.$inferSelect;
}

interface FinalizeResult {
  attachment: ReturnType<typeof formatAttachment>;
  channelId: string;
}

export interface FinalizeAttachmentInput {
  chunkCount: number;
  wrappedKey: string;
  cryptoManifest: AttachmentCryptoManifestInput;
  deviceId: string;
  keyVersion: number;
  signature: string;
}

interface AuthorizedChunk {
  stream: Readable;
  sizeBytes: number;
}


export async function createUpload(
  userId: string,
  messageId: string,
  filenameEnc: string,
  mimeType: string,
  idempotencyKey: string,
) {
  await ensureObjectStorageBucket();
  const workspaceId = await getMessageWorkspaceId(messageId);
  // The client UUID doubles as the stable reservation id. A caller can resume
  // or cancel after a lost create response without first learning a server id.
  const uploadId = idempotencyKey;
  const storageKey = `attachments/v1/${randomUUID()}`;
  const expiresAt = new Date(Date.now() + ATTACHMENT_UPLOAD_TTL_MS);

  const upload = await auditedTransaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    await lockUpload(transaction, uploadId);
    const context = await getMessageContext(transaction, messageId);
    if (!context || context.channel.workspaceId !== workspaceId || context.message.type !== 'message') {
      throw new Error('MESSAGE_NOT_FOUND');
    }
    await lockActiveAttachmentMessage(transaction, messageId);
    await assertCanAttachFromStore(transaction, userId, context.message, context.channel);
    const existing = await transaction.query.attachmentUploads.findFirst({
      where: eq(attachmentUploads.id, uploadId),
    });
    if (existing) {
      if (existing.uploaderId !== userId) throw new Error('UPLOAD_NOT_FOUND');
      const exactBody = existing.messageId === messageId
        && existing.filenameEnc === filenameEnc
        && existing.mimeType === mimeType;
      if (!exactBody || existing.completedAt) {
        throw new Error('IDEMPOTENCY_CONFLICT');
      }
      if (existing.expiresAt <= new Date()) throw new Error('UPLOAD_EXPIRED');
      return {
        upload: existing,
        workspaceId,
        channelId: context.channel.id,
        reused: true,
      };
    }

    await transaction.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`pending-uploads:workspace:${workspaceId}`})::bigint)`,
    );
    await transaction.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`pending-uploads:user:${userId}`})::bigint)`,
    );
    const now = new Date();
    const [userPending, workspacePending] = await Promise.all([
      transaction.select({ count: sql<number>`count(*)::int` })
        .from(attachmentUploads)
        .where(and(
          eq(attachmentUploads.uploaderId, userId),
          isNull(attachmentUploads.completedAt),
          gt(attachmentUploads.expiresAt, now),
        )),
      transaction.select({ count: sql<number>`count(*)::int` })
        .from(attachmentUploads)
        .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
        .innerJoin(channels, eq(messages.channelId, channels.id))
        .where(and(
          eq(channels.workspaceId, workspaceId),
          isNull(attachmentUploads.completedAt),
          gt(attachmentUploads.expiresAt, now),
        )),
    ]);
    if (Number(userPending[0]?.count ?? 0) >= MAX_PENDING_UPLOADS_PER_USER) {
      throw new Error('PENDING_UPLOAD_USER_LIMIT_REACHED');
    }
    if (Number(workspacePending[0]?.count ?? 0) >= MAX_PENDING_UPLOADS_PER_WORKSPACE) {
      throw new Error('PENDING_UPLOAD_WORKSPACE_LIMIT_REACHED');
    }

    await lockAttachmentMessageSlots(transaction, messageId);
    const [finalized, pending] = await Promise.all([
      transaction.select({ count: sql<number>`count(*)::int` })
        .from(attachments)
        .where(eq(attachments.messageId, messageId)),
      transaction.select({ count: sql<number>`count(*)::int` })
        .from(attachmentUploads)
        .where(and(
          eq(attachmentUploads.messageId, messageId),
          isNull(attachmentUploads.completedAt),
          gt(attachmentUploads.expiresAt, new Date()),
        )),
    ]);
    if (Number(finalized[0]?.count ?? 0) + Number(pending[0]?.count ?? 0) >= MAX_ATTACHMENTS_PER_MESSAGE) {
      throw new Error('ATTACHMENT_LIMIT_EXCEEDED');
    }
    const [created] = await transaction.insert(attachmentUploads).values({
      id: uploadId,
      messageId,
      uploaderId: userId,
      storageKey,
      filenameEnc,
      mimeType,
      expiresAt,
    }).returning();
    if (!created) throw new Error('UPLOAD_CREATE_FAILED');
    return { upload: created, workspaceId, channelId: context.channel.id, reused: false };
  }, ({ upload: created, workspaceId: lockedWorkspaceId, channelId, reused }) => ({
    actorId: userId,
    action: reused ? 'attachment.upload.replay' : 'attachment.upload.create',
    targetType: 'attachment_upload',
    targetId: created.id,
    details: {
      workspaceId: lockedWorkspaceId,
      channelId,
      messageId,
      expiresAt: created.expiresAt.toISOString(),
    },
  }));

  return {
    uploadId: upload.upload.id,
    reused: upload.reused,
    expiresAt: upload.upload.expiresAt.toISOString(),
    chunkPlaintextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCiphertextBytes: ATTACHMENT_CIPHERTEXT_CHUNK_BYTES,
    authenticationTagBytes: ATTACHMENT_GCM_TAG_BYTES,
    maxPlaintextBytes: MAX_FILE_SIZE,
    maxChunkCount: MAX_ATTACHMENT_CHUNKS,
    crypto: {
      version: 1,
      algorithm: 'AES-256-GCM',
      nonceStrategy: 'prefix-counter-be32',
      noncePrefixBytes: ATTACHMENT_NONCE_PREFIX_BYTES,
      aadVersion: 1,
      aadFormat: attachmentChunkAadFormat(),
    },
  };
}

export async function getUploadStatus(uploadId: string, userId: string) {
  const workspaceId = await getUploadWorkspaceId(uploadId);
  const snapshot = await db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    await lockUpload(transaction, uploadId);
    const context = await getAuthorizedPendingUpload(transaction, uploadId, userId, workspaceId);
    const chunks = await transaction.query.attachmentUploadChunks.findMany({
      where: eq(attachmentUploadChunks.uploadId, uploadId),
      orderBy: [asc(attachmentUploadChunks.chunkIndex)],
      limit: MAX_ATTACHMENT_CHUNKS + 1,
    });
    if (chunks.length > MAX_ATTACHMENT_CHUNKS) throw new Error('CHUNK_INVARIANT_EXCEEDED');
    return { context, chunks };
  });
  // Object-store probes are resumability hints, not an authorization grant.
  // Release the DB connection and workspace lock before network I/O; every
  // subsequent PUT/finalize operation re-locks and re-authorizes atomically.
  const resumableChunks: typeof snapshot.chunks = [];
  const deadline = createObjectStorageDeadline();
  for (const chunk of snapshot.chunks) {
    try {
      const stat = await statStoredObject(chunk.storageKey, deadline);
      if (stat.size === chunk.sizeBytes && normalizeEtag(stat.etag) === normalizeEtag(chunk.etag)) {
        resumableChunks.push(chunk);
      }
    } catch (error) {
      if (isObjectStorageTimeout(error)) throw error;
      // A storage write can succeed while its DB registration rolls back.
      // Treat missing/mismatched registrations as absent so a retry repairs it.
    }
  }
  return {
    uploadId,
    messageId: snapshot.context.message.id,
    expiresAt: snapshot.context.upload.expiresAt.toISOString(),
    uploadedIndexes: resumableChunks.map((chunk: typeof attachmentUploadChunks.$inferSelect) => chunk.chunkIndex),
    chunks: resumableChunks.map((chunk: typeof attachmentUploadChunks.$inferSelect) => ({
      index: chunk.chunkIndex,
      ciphertextSizeBytes: chunk.sizeBytes,
    })),
  };
}

export async function cancelUpload(uploadId: string, userId: string) {
  await ensureObjectStorageBucket();
  return withUploadOperationLock(uploadId, async () => {
    const location = await findUploadLocation(uploadId);
    // DELETE is deliberately idempotent and non-enumerating after a successful
    // cancellation: a missing UUID is indistinguishable from an already removed
    // reservation.
    if (!location) return { uploadId, cancelled: true, alreadyAbsent: true };
    if (location.upload.uploaderId !== userId) throw new Error('UPLOAD_NOT_FOUND');
    if (location.upload.completedAt) throw new Error('UPLOAD_ALREADY_COMPLETED');

    // The object store is outside every database transaction. The per-upload operation
    // lock preserves single-node ordering; the commit below re-locks and checks
    // the reservation before deleting the row and appending its audit record.
    await assertAuditWriteAvailable();
    await deleteStoredUpload(location.upload.storageKey);

    return auditedTransaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, location.workspaceId, 'share');
      await lockUpload(transaction, uploadId);
      const rows = await transaction.select({ upload: attachmentUploads, workspaceId: channels.workspaceId })
        .from(attachmentUploads)
        .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
        .innerJoin(channels, eq(messages.channelId, channels.id))
        .where(eq(attachmentUploads.id, uploadId))
        .limit(1);
      const current = rows[0];
      if (!current) return {
        uploadId,
        cancelled: true,
        alreadyAbsent: true,
        workspaceId: location.workspaceId,
        messageId: location.upload.messageId,
      };
      if (current.upload.uploaderId !== userId || current.workspaceId !== location.workspaceId) {
        throw new Error('UPLOAD_NOT_FOUND');
      }
      if (current.upload.completedAt) throw new Error('UPLOAD_ALREADY_COMPLETED');
      await lockAttachmentMessageSlots(transaction, current.upload.messageId);
      const [deleted] = await transaction.delete(attachmentUploads)
        .where(and(
          eq(attachmentUploads.id, uploadId),
          eq(attachmentUploads.uploaderId, userId),
          isNull(attachmentUploads.completedAt),
        ))
        .returning({ id: attachmentUploads.id });
      if (!deleted) throw new Error('UPLOAD_ALREADY_COMPLETED');
      return {
        uploadId,
        cancelled: true,
        alreadyAbsent: false,
        workspaceId: current.workspaceId,
        messageId: current.upload.messageId,
      };
    }, (result) => ({
      actorId: userId,
      action: result.alreadyAbsent ? 'attachment.upload.cancel.replay' : 'attachment.upload.cancel',
      targetType: 'attachment_upload',
      targetId: uploadId,
      details: {
        workspaceId: result.workspaceId,
        messageId: result.messageId,
      },
    }));
  });
}

export async function storeUploadChunk(
  uploadId: string,
  userId: string,
  chunkIndex: number,
  body: Buffer,
) {
  assertValidChunkIndex(chunkIndex);
  if (!Buffer.isBuffer(body) || body.length < ATTACHMENT_GCM_TAG_BYTES || body.length > ATTACHMENT_CIPHERTEXT_CHUNK_BYTES) {
    throw new Error('INVALID_CHUNK_SIZE');
  }
  await ensureObjectStorageBucket();
  const workspaceId = await getUploadWorkspaceId(uploadId);
  const attemptId = randomUUID();

  return withUploadOperationLock(uploadId, async () => {
    const reservation = await db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
      await lockUpload(transaction, uploadId);
      const context = await getAuthorizedPendingUpload(transaction, uploadId, userId, workspaceId);
      const existing = await transaction.query.attachmentUploadChunks.findFirst({
        where: and(
          eq(attachmentUploadChunks.uploadId, uploadId),
          eq(attachmentUploadChunks.chunkIndex, chunkIndex),
        ),
      });
      await assertChunkQuota(transaction, context, userId, body.length, existing?.sizeBytes ?? 0);
      return { storageKey: attachmentChunkStorageKey(context.upload.storageKey, chunkIndex, attemptId) };
    });

    await assertAuditWriteAvailable();
    const uploaded = await putStoredObject(reservation.storageKey, body);
    const etag = normalizeEtag(uploaded.etag);
    if (!etag) throw new Error('CHUNK_STORAGE_FAILED');

    const committed = await auditGuardedTransaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
      await lockUpload(transaction, uploadId);
      const context = await getAuthorizedPendingUpload(transaction, uploadId, userId, workspaceId);
      const existing = await transaction.query.attachmentUploadChunks.findFirst({
        where: and(
          eq(attachmentUploadChunks.uploadId, uploadId),
          eq(attachmentUploadChunks.chunkIndex, chunkIndex),
        ),
      });
      await assertChunkQuota(transaction, context, userId, body.length, existing?.sizeBytes ?? 0);
      const storageKey = attachmentChunkStorageKey(context.upload.storageKey, chunkIndex, attemptId);
      if (storageKey !== reservation.storageKey) throw new Error('UPLOAD_NOT_FOUND');
      const now = new Date();
      const [saved] = await transaction.insert(attachmentUploadChunks).values({
        uploadId,
        chunkIndex,
        sizeBytes: body.length,
        storageKey,
        etag,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      }).onConflictDoUpdate({
        target: [attachmentUploadChunks.uploadId, attachmentUploadChunks.chunkIndex],
        set: { sizeBytes: body.length, storageKey, etag, updatedAt: now },
      }).returning();
      if (!saved) throw new Error('CHUNK_STORAGE_FAILED');
      return {
        response: {
          uploadId,
          index: saved.chunkIndex,
          ciphertextSizeBytes: saved.sizeBytes,
          replaced: Boolean(existing),
        },
        previousStorageKey: existing?.storageKey ?? null,
      };
    });
    if (committed.previousStorageKey && committed.previousStorageKey !== reservation.storageKey) {
      await removeStoredObjectBestEffort(committed.previousStorageKey);
    }
    return committed.response;
  });
}

export async function preflightUploadChunk(
  uploadId: string,
  userId: string,
  chunkIndex: number,
  sizeBytes: number,
): Promise<void> {
  assertValidChunkIndex(chunkIndex);
  if (
    !Number.isSafeInteger(sizeBytes)
    || sizeBytes < ATTACHMENT_GCM_TAG_BYTES
    || sizeBytes > ATTACHMENT_CIPHERTEXT_CHUNK_BYTES
  ) throw new Error('INVALID_CHUNK_SIZE');
  const workspaceId = await getUploadWorkspaceId(uploadId);
  await db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
    await lockUpload(transaction, uploadId);
    const context = await getAuthorizedPendingUpload(transaction, uploadId, userId, workspaceId);
    const existing = await transaction.query.attachmentUploadChunks.findFirst({
      where: and(
        eq(attachmentUploadChunks.uploadId, uploadId),
        eq(attachmentUploadChunks.chunkIndex, chunkIndex),
      ),
    });
    await assertChunkQuota(transaction, context, userId, sizeBytes, existing?.sizeBytes ?? 0);
  });
}

export async function finalizeUpload(
  uploadId: string,
  userId: string,
  input: FinalizeAttachmentInput,
): Promise<FinalizeResult> {
  assertValidManifest(input.cryptoManifest);
  assertValidFinalChunkCount(input.chunkCount);
  await ensureObjectStorageBucket();
  const workspaceId = await getUploadWorkspaceId(uploadId);

  return withUploadOperationLock(uploadId, async () => {
    const snapshot = await db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
      await lockUpload(transaction, uploadId);
      return loadFinalizationSnapshot(transaction, uploadId, userId, workspaceId, input);
    });

    // Object storage is authoritative for the bytes, but it must never occupy
    // a PostgreSQL connection. The short commit transaction below repeats all
    // authorization/signature/quota checks and requires the exact same chunk
    // registrations observed here.
    await assertAuditWriteAvailable();
    await verifyRegisteredChunkObjects(snapshot.chunkRows);
    const expectedObjectKeys = new Set(snapshot.chunkRows.map((chunk) => chunk.storageKey));
    await reconcileStoredUpload(snapshot.context.upload.storageKey, expectedObjectKeys);

    const finalized = await auditedTransaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, workspaceId, 'share');
      await lockUpload(transaction, uploadId);
      const current = await loadFinalizationSnapshot(transaction, uploadId, userId, workspaceId, input);
      if (!sameChunkRegistrations(snapshot.chunkRows, current.chunkRows)) {
        throw new Error('CHUNK_OBJECT_MISMATCH');
      }

      const completedAt = new Date();
      const [claimed] = await transaction.update(attachmentUploads)
        .set({ completedAt })
        .where(and(
          eq(attachmentUploads.id, uploadId),
          eq(attachmentUploads.uploaderId, userId),
          isNull(attachmentUploads.completedAt),
          gt(attachmentUploads.expiresAt, completedAt),
        ))
        .returning();
      if (!claimed) throw new Error('UPLOAD_ALREADY_COMPLETED');

      const storedManifest: StoredAttachmentCryptoManifest = {
        ...input.cryptoManifest,
        chunkPlaintextBytes: ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
        authenticationTagBytes: ATTACHMENT_GCM_TAG_BYTES,
        chunkCount: input.chunkCount,
        uploadId,
        messageId: current.context.message.id,
        aadFormat: attachmentChunkAadFormat(),
      };
      const [created] = await transaction.insert(attachments).values({
        messageId: current.context.message.id,
        channelId: current.context.channel.id,
        signerDeviceId: input.deviceId,
        keyVersion: input.keyVersion,
        signature: input.signature,
        filenameEnc: current.context.upload.filenameEnc,
        mimeType: current.context.upload.mimeType,
        sizeBytes: current.layout.ciphertextSizeBytes,
        storageKey: current.context.upload.storageKey,
        chunkCount: input.chunkCount,
        wrappedKey: input.wrappedKey,
        contentNonce: input.cryptoManifest.noncePrefix,
        cryptoManifest: storedManifest,
        thumbnailKey: null,
      }).returning();
      if (!created) throw new Error('ATTACHMENT_CREATE_FAILED');
      return {
        attachment: formatAttachment(created),
        channelId: current.context.channel.id,
        workspaceId,
        plaintextSizeBytes: current.layout.plaintextSizeBytes,
      };
    }, (result) => ({
      actorId: userId,
      action: 'attachment.create',
      targetType: 'attachment',
      targetId: result.attachment.id,
      details: {
        workspaceId: result.workspaceId,
        channelId: result.channelId,
        messageId: result.attachment.messageId,
        chunkCount: result.attachment.chunkCount,
        ciphertextSizeBytes: result.attachment.sizeBytes,
        plaintextSizeBytes: result.plaintextSizeBytes,
      },
    }));
    // A crashed or superseded attempt may have completed after the first
    // reconciliation. It cannot become authoritative because registrations
    // were frozen above; remove it best-effort without changing the committed
    // attachment response.
    await reconcileStoredUpload(snapshot.context.upload.storageKey, expectedObjectKeys).catch(() => undefined);
    return finalized;
  });
}

export async function getAuthorizedAttachmentMetadata(attachmentId: string, userId: string) {
  const attachment = await getAuthorizedAttachment(attachmentId, userId);
  return formatAttachment(attachment);
}

export async function getAuthorizedAttachmentChunk(
  attachmentId: string,
  chunkIndex: number,
  userId: string,
): Promise<AuthorizedChunk> {
  const releaseDownload = acquireDownloadLease(userId);
  if (!releaseDownload) throw new Error('DOWNLOAD_LIMIT_REACHED');
  try {
    const location = await db.select({ workspaceId: channels.workspaceId })
      .from(attachments)
      .innerJoin(messages, eq(attachments.messageId, messages.id))
      .innerJoin(channels, eq(messages.channelId, channels.id))
      .where(eq(attachments.id, attachmentId))
      .limit(1);
    if (!location[0]) throw new Error('ATTACHMENT_NOT_FOUND');
    const authorized = await db.transaction(async (transaction) => {
      await lockWorkspaceForAuthorization(transaction, location[0].workspaceId, 'share');
      const rows = await transaction.select({ attachment: attachments, message: messages, channel: channels })
        .from(attachments)
        .innerJoin(messages, eq(attachments.messageId, messages.id))
        .innerJoin(channels, eq(messages.channelId, channels.id))
        .where(eq(attachments.id, attachmentId))
        .limit(1);
      const context = rows[0];
      if (!context || context.channel.workspaceId !== location[0].workspaceId) throw new Error('ATTACHMENT_NOT_FOUND');
      try {
        await lockActiveAttachmentMessage(transaction, context.message.id);
      } catch {
        throw new Error('ATTACHMENT_NOT_FOUND');
      }
      if (!await canViewChannelFromStore(transaction, userId, context.channel)) throw new Error('ATTACHMENT_NOT_FOUND');
      if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= context.attachment.chunkCount) {
        throw new Error('ATTACHMENT_NOT_FOUND');
      }
      const manifest = context.attachment.cryptoManifest as Partial<StoredAttachmentCryptoManifest> | null;
      if (manifest?.version === 1 && typeof manifest.uploadId === 'string') {
        const chunk = await transaction.query.attachmentUploadChunks.findFirst({
          where: and(
            eq(attachmentUploadChunks.uploadId, manifest.uploadId),
            eq(attachmentUploadChunks.chunkIndex, chunkIndex),
          ),
        });
        if (!chunk) throw new Error('ATTACHMENT_NOT_FOUND');
        return { storageKey: chunk.storageKey, expectedSizeBytes: chunk.sizeBytes };
      }
      if (chunkIndex !== 0) throw new Error('ATTACHMENT_NOT_FOUND');
      return { storageKey: context.attachment.storageKey, expectedSizeBytes: context.attachment.sizeBytes };
    });

    try {
      const deadline = createObjectStorageDeadline();
      const stat = await statStoredObject(authorized.storageKey, deadline);
      if (stat.size !== authorized.expectedSizeBytes) throw new Error('ATTACHMENT_NOT_FOUND');
      const stream = await getStoredObject(authorized.storageKey, authorized.expectedSizeBytes);
      const release = () => releaseDownload();
      stream.once('end', release);
      stream.once('close', release);
      stream.once('error', release);
      // Authorization is snapshot semantics at request acceptance. No database
      // connection or workspace lock is held while the object store or the client is slow.
      return { stream, sizeBytes: stat.size };
    } catch (error) {
      if (isObjectStorageTimeout(error) || (error instanceof Error && error.message === 'OBJECT_STORAGE_BUSY')) throw error;
      throw new Error('ATTACHMENT_NOT_FOUND');
    }
  } catch (error) {
    releaseDownload();
    throw error;
  }
}

export async function getAttachmentsForMessages(messageIds: string[], store: typeof db = db) {
  const grouped = new Map<string, ReturnType<typeof formatAttachment>[]>();
  if (messageIds.length === 0) return grouped;
  const rows = await store.query.attachments.findMany({
    where: inArray(attachments.messageId, messageIds),
    orderBy: [asc(attachments.createdAt), asc(attachments.id)],
    limit: messageIds.length * MAX_ATTACHMENTS_PER_MESSAGE + 1,
  });
  if (rows.length > messageIds.length * MAX_ATTACHMENTS_PER_MESSAGE) {
    throw new Error('ATTACHMENT_INVARIANT_EXCEEDED');
  }
  for (const row of rows) {
    const existing = grouped.get(row.messageId) ?? [];
    existing.push(formatAttachment(row));
    grouped.set(row.messageId, existing);
  }
  return grouped;
}

export async function cleanupExpiredUploads(limit = 100): Promise<number> {
  const expired = await db.query.attachmentUploads.findMany({
    columns: { id: true },
    where: and(isNull(attachmentUploads.completedAt), lte(attachmentUploads.expiresAt, new Date())),
    orderBy: [asc(attachmentUploads.expiresAt)],
    limit,
  });
  let removed = 0;
  const failures: unknown[] = [];
  for (const candidate of expired) {
    try {
      const deleted = await withUploadOperationLock(candidate.id, async () => {
        const upload = await db.transaction(async (transaction) => {
          await lockUpload(transaction, candidate.id);
          return transaction.query.attachmentUploads.findFirst({
            where: and(
              eq(attachmentUploads.id, candidate.id),
              isNull(attachmentUploads.completedAt),
              lte(attachmentUploads.expiresAt, new Date()),
            ),
          });
        });
        if (!upload) return false;
        await assertAuditWriteAvailable();
        await deleteStoredUpload(upload.storageKey);
        return auditGuardedTransaction(async (transaction) => {
          await lockUpload(transaction, candidate.id);
          const [removedUpload] = await transaction.delete(attachmentUploads)
            .where(and(
              eq(attachmentUploads.id, upload.id),
              isNull(attachmentUploads.completedAt),
              lte(attachmentUploads.expiresAt, new Date()),
            ))
            .returning({ id: attachmentUploads.id });
          return Boolean(removedUpload);
        });
      });
      if (deleted) removed += 1;
    } catch (error) {
      // Keep the upload row so the next cleanup pass can retry storage removal.
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, `Failed to clean ${failures.length} expired attachment upload(s)`);
  }
  return removed;
}

async function getAuthorizedAttachment(attachmentId: string, userId: string) {
  const location = await db.select({ workspaceId: channels.workspaceId })
    .from(attachments)
    .innerJoin(messages, eq(attachments.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(attachments.id, attachmentId))
    .limit(1);
  if (!location[0]) throw new Error('ATTACHMENT_NOT_FOUND');
  return db.transaction(async (transaction) => {
    await lockWorkspaceForAuthorization(transaction, location[0].workspaceId, 'share');
    const rows = await transaction.select({ attachment: attachments, message: messages, channel: channels })
      .from(attachments)
      .innerJoin(messages, eq(attachments.messageId, messages.id))
      .innerJoin(channels, eq(messages.channelId, channels.id))
      .where(eq(attachments.id, attachmentId))
      .limit(1);
    const context = rows[0];
    if (!context || context.channel.workspaceId !== location[0].workspaceId) throw new Error('ATTACHMENT_NOT_FOUND');
    try {
      await lockActiveAttachmentMessage(transaction, context.message.id);
    } catch {
      throw new Error('ATTACHMENT_NOT_FOUND');
    }
    if (!await canViewChannelFromStore(transaction, userId, context.channel)) throw new Error('ATTACHMENT_NOT_FOUND');
    return context.attachment;
  });
}

async function loadFinalizationSnapshot(
  store: any,
  uploadId: string,
  userId: string,
  workspaceId: string,
  input: FinalizeAttachmentInput,
) {
  const context = await getAuthorizedPendingUpload(store, uploadId, userId, workspaceId);
  const [device] = await store.select()
    .from(devices)
    .where(and(eq(devices.id, input.deviceId), eq(devices.userId, userId), isNull(devices.revokedAt), isNotNull(devices.approvedAt)))
    .for('share');
  if (!device) throw new Error('INVALID_DEVICE');
  if (context.channel.keyRotationRequired) throw new Error('KEY_ROTATION_REQUIRED');
  const epoch = await store.query.channelKeyEpochs.findFirst({
    columns: { version: true, createdAt: true },
    where: and(
      eq(channelKeyEpochs.channelId, context.channel.id),
      eq(channelKeyEpochs.version, input.keyVersion),
      eq(channelKeyEpochs.status, 'active'),
      eq(channelKeyEpochs.protocolVersion, 3),
    ),
  });
  if (!epoch) throw new Error('INVALID_KEY_VERSION');
  if (Date.now() - epoch.createdAt.getTime() >= 24 * 60 * 60_000 || !await isEpochRosterCurrent(store, context.channel, input.keyVersion)) throw new Error('KEY_ROTATION_REQUIRED');
  if (await hasRevokedEpochRecipient(store, context.channel.id, input.keyVersion)) {
    throw new Error('KEY_ROTATION_REQUIRED');
  }
  const recipient = await store.query.channelKeyEpochRecipients.findFirst({
    columns: { acceptedDeliveryId: true },
    where: and(
      eq(channelKeyEpochRecipients.channelId, context.channel.id),
      eq(channelKeyEpochRecipients.version, input.keyVersion),
      eq(channelKeyEpochRecipients.deviceId, input.deviceId),
      eq(channelKeyEpochRecipients.userId, userId),
      isNotNull(channelKeyEpochRecipients.acceptedDeliveryId),
    ),
  });
  if (!recipient?.acceptedDeliveryId) throw new Error('INVALID_KEY_VERSION');
  const envelope: SignedAttachmentEnvelope = {
    type: 'attachment',
    uploadId,
    messageId: context.message.id,
    channelId: context.channel.id,
    authorId: userId,
    deviceId: input.deviceId,
    keyVersion: input.keyVersion,
    filenameEnc: context.upload.filenameEnc,
    mimeType: context.upload.mimeType,
    wrappedKey: input.wrappedKey,
    noncePrefix: input.cryptoManifest.noncePrefix,
    plaintextSize: input.cryptoManifest.plaintextSize,
    chunkCount: input.chunkCount,
  };
  // Current clients bind the file to the message's signed idempotency key;
  // older clients still sign the legacy layout, which readers also accept.
  const messageIdempotencyKey = signedIdempotencyKey(context.message);
  const bound = messageIdempotencyKey ? { ...envelope, messageIdempotencyKey } : null;
  if (
    !(bound && verifyAttachmentEnvelopeSignature(device.identityKey, bound, input.signature))
    && !verifyAttachmentEnvelopeSignature(device.identityKey, envelope, input.signature)
  ) {
    throw new Error('INVALID_SIGNATURE');
  }
  const chunkRows = await store.query.attachmentUploadChunks.findMany({
    where: eq(attachmentUploadChunks.uploadId, uploadId),
    orderBy: [asc(attachmentUploadChunks.chunkIndex)],
    limit: MAX_ATTACHMENT_CHUNKS + 1,
  }) as Array<typeof attachmentUploadChunks.$inferSelect>;
  if (chunkRows.length > MAX_ATTACHMENT_CHUNKS) throw new Error('CHUNK_INVARIANT_EXCEEDED');
  const layout = validateFinalChunkLayout(input.chunkCount, input.cryptoManifest, chunkRows);
  await lockQuotaScopes(store, context.channel.workspaceId, context.channel.id, userId);
  const used = await getCiphertextUsage(store, context.channel.workspaceId, context.channel.id, userId);
  if (
    used.userBytes > config.storage.perUserQuotaBytes
    || used.channelBytes > config.storage.perChannelQuotaBytes
    || used.workspaceBytes > config.storage.perWorkspaceQuotaBytes
  ) {
    throw new Error('STORAGE_QUOTA_EXCEEDED');
  }
  return { context, chunkRows, layout };
}

async function verifyRegisteredChunkObjects(
  chunks: Array<typeof attachmentUploadChunks.$inferSelect>,
): Promise<void> {
  const deadline = createObjectStorageDeadline();
  for (const chunk of chunks) {
    let stat;
    try {
      stat = await statStoredObject(chunk.storageKey, deadline);
    } catch (error) {
      if (isObjectStorageTimeout(error)) throw error;
      throw new Error('CHUNK_OBJECT_MISSING');
    }
    if (stat.size !== chunk.sizeBytes || normalizeEtag(stat.etag) !== normalizeEtag(chunk.etag)) {
      throw new Error('CHUNK_OBJECT_MISMATCH');
    }
  }
}

function sameChunkRegistrations(
  expected: Array<typeof attachmentUploadChunks.$inferSelect>,
  current: Array<typeof attachmentUploadChunks.$inferSelect>,
): boolean {
  return expected.length === current.length && expected.every((chunk, index) => {
    const other = current[index];
    return other?.chunkIndex === chunk.chunkIndex
      && other.sizeBytes === chunk.sizeBytes
      && other.storageKey === chunk.storageKey
      && normalizeEtag(other.etag) === normalizeEtag(chunk.etag);
  });
}

async function getAuthorizedPendingUpload(
  store: any,
  uploadId: string,
  userId: string,
  workspaceId: string,
): Promise<UploadContext> {
  const rows = await store.select({ upload: attachmentUploads, message: messages, channel: channels })
    .from(attachmentUploads)
    .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(attachmentUploads.id, uploadId))
    .limit(1);
  const context = rows[0] as UploadContext | undefined;
  if (!context || context.upload.uploaderId !== userId || context.channel.workspaceId !== workspaceId) {
    throw new Error('UPLOAD_NOT_FOUND');
  }
  if (context.upload.completedAt) throw new Error('UPLOAD_ALREADY_COMPLETED');
  if (context.upload.expiresAt <= new Date()) throw new Error('UPLOAD_NOT_FOUND');
  if (context.message.type !== 'message') throw new Error('MESSAGE_NOT_FOUND');
  await lockActiveAttachmentMessage(store, context.message.id);
  await assertCanAttachFromStore(store, userId, context.message, context.channel);
  return context;
}

async function assertChunkQuota(
  store: any,
  context: UploadContext,
  userId: string,
  candidateBytes: number,
  replacedBytes: number,
): Promise<void> {
  await lockQuotaScopes(store, context.channel.workspaceId, context.channel.id, userId);
  const used = await getCiphertextUsage(store, context.channel.workspaceId, context.channel.id, userId);
  const nextUserUsage = used.userBytes - replacedBytes + candidateBytes;
  const nextChannelUsage = used.channelBytes - replacedBytes + candidateBytes;
  const nextWorkspaceUsage = used.workspaceBytes - replacedBytes + candidateBytes;
  if (
    !Number.isSafeInteger(nextUserUsage)
    || !Number.isSafeInteger(nextChannelUsage)
    || !Number.isSafeInteger(nextWorkspaceUsage)
    || nextUserUsage > config.storage.perUserQuotaBytes
    || nextChannelUsage > config.storage.perChannelQuotaBytes
    || nextWorkspaceUsage > config.storage.perWorkspaceQuotaBytes
  ) {
    throw new Error('STORAGE_QUOTA_EXCEEDED');
  }
}

async function getMessageWorkspaceId(messageId: string): Promise<string> {
  const rows = await db.select({ workspaceId: channels.workspaceId })
    .from(messages)
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(and(eq(messages.id, messageId), eq(messages.type, 'message')))
    .limit(1);
  if (!rows[0]) throw new Error('MESSAGE_NOT_FOUND');
  return rows[0].workspaceId;
}

async function getUploadWorkspaceId(uploadId: string): Promise<string> {
  const rows = await db.select({ workspaceId: channels.workspaceId })
    .from(attachmentUploads)
    .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(attachmentUploads.id, uploadId))
    .limit(1);
  if (!rows[0]) throw new Error('UPLOAD_NOT_FOUND');
  return rows[0].workspaceId;
}

async function findUploadLocation(uploadId: string) {
  const rows = await db.select({ upload: attachmentUploads, workspaceId: channels.workspaceId })
    .from(attachmentUploads)
    .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(attachmentUploads.id, uploadId))
    .limit(1);
  return rows[0];
}

async function getMessageContext(store: any, messageId: string) {
  const rows = await store.select({ message: messages, channel: channels })
    .from(messages)
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(messages.id, messageId))
    .limit(1);
  return rows[0] as { message: typeof messages.$inferSelect; channel: typeof channels.$inferSelect } | undefined;
}

async function assertCanAttachFromStore(
  store: any,
  userId: string,
  message: typeof messages.$inferSelect,
  channel: typeof channels.$inferSelect,
): Promise<void> {
  if (message.authorId !== userId) throw new Error('NOT_AUTHORIZED');
  const authorization = await getChannelAuthorizationFromStore(store, userId, channel);
  if (!isVisibleChannelAuthorization(authorization)) throw new Error('MESSAGE_NOT_FOUND');
  if ((authorization.permissions & Permissions.ATTACH_FILES) !== Permissions.ATTACH_FILES) throw new Error('NOT_AUTHORIZED');
}

async function canViewChannelFromStore(
  store: any,
  userId: string,
  channel: typeof channels.$inferSelect,
): Promise<boolean> {
  return isVisibleChannelAuthorization(await getChannelAuthorizationFromStore(store, userId, channel));
}

export async function getCiphertextUsage(store: any, workspaceId: string, channelId: string, userId: string) {
  const finalizedUserRows = await store.select({
    bytes: sql<string>`coalesce(sum(${attachments.sizeBytes}), 0)::bigint`,
  }).from(attachments)
    .innerJoin(messages, eq(attachments.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(and(eq(messages.authorId, userId), eq(channels.workspaceId, workspaceId)));
  const activeUserRows = await store.select({
    bytes: sql<string>`coalesce(sum(${attachmentUploadChunks.sizeBytes}), 0)::bigint`,
  }).from(attachmentUploadChunks)
    .innerJoin(attachmentUploads, eq(attachmentUploadChunks.uploadId, attachmentUploads.id))
    .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(and(eq(attachmentUploads.uploaderId, userId), eq(channels.workspaceId, workspaceId), isNull(attachmentUploads.completedAt)));
  const finalizedRows = await store.select({
    channelBytes: sql<string>`coalesce(sum(${attachments.sizeBytes}) filter (where ${messages.channelId} = ${channelId}), 0)::bigint`,
    workspaceBytes: sql<string>`coalesce(sum(${attachments.sizeBytes}), 0)::bigint`,
  }).from(attachments)
    .innerJoin(messages, eq(attachments.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(eq(channels.workspaceId, workspaceId));
  const activeRows = await store.select({
    channelBytes: sql<string>`coalesce(sum(${attachmentUploadChunks.sizeBytes}) filter (where ${messages.channelId} = ${channelId}), 0)::bigint`,
    workspaceBytes: sql<string>`coalesce(sum(${attachmentUploadChunks.sizeBytes}), 0)::bigint`,
  }).from(attachmentUploadChunks)
    .innerJoin(attachmentUploads, eq(attachmentUploadChunks.uploadId, attachmentUploads.id))
    .innerJoin(messages, eq(attachmentUploads.messageId, messages.id))
    .innerJoin(channels, eq(messages.channelId, channels.id))
    .where(and(eq(channels.workspaceId, workspaceId), isNull(attachmentUploads.completedAt)));
  const result = {
    userBytes: Number(finalizedUserRows[0]?.bytes ?? 0) + Number(activeUserRows[0]?.bytes ?? 0),
    channelBytes: Number(finalizedRows[0]?.channelBytes ?? 0) + Number(activeRows[0]?.channelBytes ?? 0),
    workspaceBytes: Number(finalizedRows[0]?.workspaceBytes ?? 0) + Number(activeRows[0]?.workspaceBytes ?? 0),
  };
  if (!Object.values(result).every(Number.isSafeInteger)) throw new Error('STORAGE_QUOTA_EXCEEDED');
  return result;
}

export const MAX_UPLOAD_OPERATIONS_PER_UPLOAD = 4;
export const MAX_UPLOAD_OPERATIONS_TOTAL = 64;

interface UploadOperationState {
  tail: Promise<void>;
  outstanding: number;
}

const uploadOperationStates = new Map<string, UploadOperationState>();
let outstandingUploadOperations = 0;

/**
 * The supported deployment is one application node. Serialize every object-store
 * phase for a reservation without retaining a database connection, then let
 * each short database phase re-lock and re-authorize its own state transition.
 */
export async function withUploadOperationLock<T>(uploadId: string, operation: () => Promise<T>): Promise<T> {
  const state = uploadOperationStates.get(uploadId) ?? { tail: Promise.resolve(), outstanding: 0 };
  if (
    state.outstanding >= MAX_UPLOAD_OPERATIONS_PER_UPLOAD
    || outstandingUploadOperations >= MAX_UPLOAD_OPERATIONS_TOTAL
  ) throw new Error('UPLOAD_OPERATION_BUSY');

  const predecessor = state.tail;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  state.tail = predecessor.catch(() => undefined).then(() => gate);
  state.outstanding += 1;
  outstandingUploadOperations += 1;
  uploadOperationStates.set(uploadId, state);
  await predecessor.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    state.outstanding -= 1;
    outstandingUploadOperations -= 1;
    if (state.outstanding === 0 && uploadOperationStates.get(uploadId) === state) {
      uploadOperationStates.delete(uploadId);
    }
  }
}

async function lockUpload(store: any, uploadId: string): Promise<void> {
  await store.execute(
    sql`select pg_advisory_xact_lock(hashtext(${`attachment-upload:${uploadId}`})::bigint)`,
  );
}

async function lockAttachmentMessageSlots(store: any, messageId: string): Promise<void> {
  await store.execute(
    sql`select pg_advisory_xact_lock(hashtext(${`attachment-message:${messageId}`})::bigint)`,
  );
}

async function lockActiveAttachmentMessage(store: any, messageId: string) {
  const [message] = await store.select()
    .from(messages)
    .where(and(eq(messages.id, messageId), eq(messages.type, 'message')))
    .for('share');
  if (!message) throw new Error('MESSAGE_NOT_FOUND');
  const deleted = await store.query.messages.findFirst({
    columns: { id: true },
    where: and(eq(messages.refMessageId, messageId), eq(messages.type, 'delete')),
  });
  if (deleted) throw new Error('MESSAGE_NOT_FOUND');
  return message;
}

async function lockQuotaScopes(store: any, workspaceId: string, channelId: string, userId: string): Promise<void> {
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${`attachment-quota:workspace:${workspaceId}`})::bigint)`);
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${`attachment-quota:channel:${channelId}`})::bigint)`);
  await store.execute(sql`select pg_advisory_xact_lock(hashtext(${`attachment-quota:user:${userId}`})::bigint)`);
}

function normalizeEtag(etag: string | undefined): string {
  return (etag ?? '').replace(/^"|"$/g, '').trim().toLowerCase();
}

function formatAttachment(attachment: typeof attachments.$inferSelect) {
  const manifest = attachment.cryptoManifest as Partial<StoredAttachmentCryptoManifest> | null;
  const plaintextSizeBytes = manifest?.version === 1 && Number.isSafeInteger(manifest.plaintextSize)
    ? manifest.plaintextSize
    : null;
  return {
    id: attachment.id,
    messageId: attachment.messageId,
    channelId: attachment.channelId,
    keyVersion: attachment.keyVersion,
    deviceId: attachment.signerDeviceId,
    signature: attachment.signature,
    filenameEnc: attachment.filenameEnc,
    mimeType: attachment.mimeType,
    dangerousMime: isDangerousAttachmentMime(attachment.mimeType),
    downloadPolicy: 'attachment-only' as const,
    sizeBytes: attachment.sizeBytes,
    ciphertextSizeBytes: attachment.sizeBytes,
    plaintextSizeBytes,
    chunkCount: attachment.chunkCount,
    wrappedKey: attachment.wrappedKey,
    contentNonce: attachment.contentNonce,
    cryptoManifest: attachment.cryptoManifest,
    thumbnailKey: null,
    createdAt: attachment.createdAt.toISOString(),
  };
}
