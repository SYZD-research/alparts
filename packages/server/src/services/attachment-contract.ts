import {
  ATTACHMENT_CHUNK_AAD_FORMAT,
  ATTACHMENT_GCM_TAG_BYTES as SHARED_ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES as SHARED_ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_FILE_SIZE,
  serializeAttachmentChunkAad,
} from '@alparts/shared';

export const ATTACHMENT_PLAINTEXT_CHUNK_BYTES = SHARED_ATTACHMENT_PLAINTEXT_CHUNK_BYTES;
export const ATTACHMENT_GCM_TAG_BYTES = SHARED_ATTACHMENT_GCM_TAG_BYTES;
export const ATTACHMENT_CIPHERTEXT_CHUNK_BYTES = ATTACHMENT_PLAINTEXT_CHUNK_BYTES + ATTACHMENT_GCM_TAG_BYTES;
export const MAX_ATTACHMENT_CHUNKS = Math.ceil(MAX_FILE_SIZE / ATTACHMENT_PLAINTEXT_CHUNK_BYTES);
export const MAX_ATTACHMENTS_PER_MESSAGE = 4;
export const ATTACHMENT_UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;

export interface AttachmentCryptoManifestInput {
  version: 1;
  algorithm: 'AES-256-GCM';
  nonceStrategy: 'prefix-counter-be32';
  noncePrefix: string;
  aadVersion: 1;
  plaintextSize: number;
}

interface ChunkLayoutRow {
  chunkIndex: number;
  sizeBytes: number;
}

export function validateFinalChunkLayout(
  chunkCount: number,
  manifest: AttachmentCryptoManifestInput,
  chunkRows: ChunkLayoutRow[],
) {
  assertValidManifest(manifest);
  assertValidFinalChunkCount(chunkCount);
  if (chunkRows.length !== chunkCount) throw new Error('INVALID_CHUNK_LAYOUT');
  let ciphertextSizeBytes = 0;
  for (let index = 0; index < chunkRows.length; index += 1) {
    const chunk = chunkRows[index];
    if (chunk.chunkIndex !== index) throw new Error('INVALID_CHUNK_LAYOUT');
    const isFinal = index === chunkCount - 1;
    if (!Number.isSafeInteger(chunk.sizeBytes)) throw new Error('INVALID_CHUNK_SIZE');
    if (!isFinal && chunk.sizeBytes !== ATTACHMENT_CIPHERTEXT_CHUNK_BYTES) {
      throw new Error('INVALID_CHUNK_SIZE');
    }
    if (isFinal && (chunk.sizeBytes < ATTACHMENT_GCM_TAG_BYTES || chunk.sizeBytes > ATTACHMENT_CIPHERTEXT_CHUNK_BYTES)) {
      throw new Error('INVALID_CHUNK_SIZE');
    }
    ciphertextSizeBytes += chunk.sizeBytes;
  }
  const plaintextSizeBytes = ciphertextSizeBytes - chunkCount * ATTACHMENT_GCM_TAG_BYTES;
  const expectedChunkCount = Math.max(1, Math.ceil(manifest.plaintextSize / ATTACHMENT_PLAINTEXT_CHUNK_BYTES));
  if (
    !Number.isSafeInteger(ciphertextSizeBytes)
    || plaintextSizeBytes < 0
    || plaintextSizeBytes > MAX_FILE_SIZE
    || plaintextSizeBytes !== manifest.plaintextSize
    || chunkCount !== expectedChunkCount
  ) {
    throw new Error('INVALID_CHUNK_LAYOUT');
  }
  return { ciphertextSizeBytes, plaintextSizeBytes };
}

export function assertValidManifest(manifest: AttachmentCryptoManifestInput): void {
  if (
    !manifest
    || manifest.version !== 1
    || manifest.algorithm !== 'AES-256-GCM'
    || manifest.nonceStrategy !== 'prefix-counter-be32'
    || manifest.aadVersion !== 1
    || !Number.isSafeInteger(manifest.plaintextSize)
    || manifest.plaintextSize < 0
    || manifest.plaintextSize > MAX_FILE_SIZE
    || !isCanonicalBase64Bytes(manifest.noncePrefix, 8)
  ) {
    throw new Error('INVALID_CRYPTO_MANIFEST');
  }
}

export function assertValidChunkIndex(chunkIndex: number): void {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= MAX_ATTACHMENT_CHUNKS) {
    throw new Error('INVALID_CHUNK_INDEX');
  }
}

export function assertValidFinalChunkCount(chunkCount: number): void {
  if (!Number.isSafeInteger(chunkCount) || chunkCount < 1 || chunkCount > MAX_ATTACHMENT_CHUNKS) {
    throw new Error('INVALID_CHUNK_COUNT');
  }
}

export function attachmentChunkStorageKey(storagePrefix: string, chunkIndex: number, attemptId?: string): string {
  const base = `${storagePrefix}/${String(chunkIndex).padStart(6, '0')}`;
  return attemptId ? `${base}/${attemptId}` : base;
}

export function attachmentChunkAadFormat(): string {
  return ATTACHMENT_CHUNK_AAD_FORMAT;
}

export function attachmentChunkAad(
  uploadId: string,
  messageId: string,
  index: number,
  chunkCount: number,
  plaintextSize: number,
): Buffer {
  return Buffer.from(serializeAttachmentChunkAad(uploadId, messageId, index, chunkCount, plaintextSize), 'utf8');
}

export function isDangerousAttachmentMime(mimeType: string): boolean {
  const normalized = mimeType.trim().toLowerCase().split(';', 1)[0];
  return normalized === 'text/html'
    || normalized === 'image/svg+xml'
    || normalized === 'application/xhtml+xml'
    || normalized === 'application/xml'
    || normalized === 'text/xml'
    || normalized === 'application/javascript'
    || normalized === 'text/javascript'
    || normalized === 'application/wasm'
    || normalized === 'application/pdf'
    || normalized === 'application/x-sh'
    || normalized === 'application/x-httpd-php'
    || normalized === 'application/x-msdownload';
}

function isCanonicalBase64Bytes(value: unknown, expectedBytes: number): value is string {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === expectedBytes && decoded.toString('base64') === value;
}
