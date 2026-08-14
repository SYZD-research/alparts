import * as Minio from 'minio';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { attachments } from '../db/schema.js';
import { eq } from 'drizzle-orm';

const minioClient = new Minio.Client({
  endPoint: config.minio.endPoint,
  port: config.minio.port,
  useSSL: config.minio.useSSL,
  accessKey: config.minio.accessKey,
  secretKey: config.minio.secretKey,
});

async function ensureBucket() {
  const exists = await minioClient.bucketExists(config.minio.bucket);
  if (!exists) {
    await minioClient.makeBucket(config.minio.bucket);
  }
}

export async function getUploadUrl(messageId: string, filename: string, mimeType: string) {
  await ensureBucket();

  const storageKey = `${messageId}/${Date.now()}-${filename}`;
  const url = await minioClient.presignedPutObject(
    config.minio.bucket,
    storageKey,
    3600, // 1 hour expiry
  );

  return { url, storageKey };
}

export async function getDownloadUrl(storageKey: string) {
  return minioClient.presignedGetObject(
    config.minio.bucket,
    storageKey,
    3600, // 1 hour expiry
  );
}

export async function saveAttachment(params: {
  messageId: string;
  filenameEnc: string;
  mimeType: string;
  sizeBytes: number;
  storageKey: string;
  encryptionKey: string;
  thumbnailKey?: string;
}) {
  const [attachment] = await db.insert(attachments).values({
    messageId: params.messageId,
    filenameEnc: params.filenameEnc,
    mimeType: params.mimeType,
    sizeBytes: params.sizeBytes,
    storageKey: params.storageKey,
    encryptionKey: params.encryptionKey,
    thumbnailKey: params.thumbnailKey || null,
  }).returning();

  return {
    id: attachment.id,
    messageId: attachment.messageId,
    filenameEnc: attachment.filenameEnc,
    mimeType: attachment.mimeType,
    sizeBytes: attachment.sizeBytes,
    storageKey: attachment.storageKey,
    encryptionKey: attachment.encryptionKey,
    thumbnailKey: attachment.thumbnailKey,
    createdAt: attachment.createdAt.toISOString(),
  };
}

export async function getAttachmentById(attachmentId: string) {
  return db.query.attachments.findFirst({
    where: eq(attachments.id, attachmentId),
  });
}
