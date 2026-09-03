import {
  ATTACHMENT_CHUNK_AAD_FORMAT as SHARED_ATTACHMENT_CHUNK_AAD_FORMAT,
  ATTACHMENT_GCM_TAG_BYTES as SHARED_ATTACHMENT_GCM_TAG_BYTES,
  ATTACHMENT_NONCE_PREFIX_BYTES as SHARED_ATTACHMENT_NONCE_PREFIX_BYTES,
  ATTACHMENT_PLAINTEXT_CHUNK_BYTES as SHARED_ATTACHMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_FILE_SIZE,
  serializeAttachmentChunkAad,
  serializeAttachmentFilenameAad,
  serializeAttachmentWrappedKeyAad,
  type Attachment,
  type Message,
  type SignedAttachmentEnvelope,
} from '@alparts/shared';
import { api } from './api';
import { getChannelKeyForVersion, verifyAttachmentSignature } from './crypto.service';

export const ATTACHMENT_PLAINTEXT_CHUNK_BYTES = SHARED_ATTACHMENT_PLAINTEXT_CHUNK_BYTES;
export const ATTACHMENT_GCM_TAG_BYTES = SHARED_ATTACHMENT_GCM_TAG_BYTES;
export const ATTACHMENT_NONCE_PREFIX_BYTES = SHARED_ATTACHMENT_NONCE_PREFIX_BYTES;
export const ATTACHMENT_MAX_COUNT_PER_MESSAGE = 4;
export const ATTACHMENT_FALLBACK_BLOB_LIMIT_BYTES = MAX_FILE_SIZE;
export const ATTACHMENT_CHUNK_AAD_FORMAT = SHARED_ATTACHMENT_CHUNK_AAD_FORMAT;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const DIRECTORY_CACHE_TTL_MS = 60_000;
const DIRECTORY_CACHE_LIMIT = 32;

type DeviceDirectoryEntry = { deviceId: string; userId: string; identityKey: string };
const directoryCache = new Map<string, { expiresAt: number; entry: DeviceDirectoryEntry | null }>();
const directoryPromises = new Map<string, Promise<DeviceDirectoryEntry | null>>();
let directoryCacheGeneration = 0;

export interface ValidatedAttachmentManifest {
  uploadId: string;
  messageId: string;
  chunkCount: number;
  plaintextSize: number;
  noncePrefix: Uint8Array;
}

export function attachmentFilenameAad(messageId: string): Uint8Array {
  return encoder.encode(serializeAttachmentFilenameAad(messageId));
}

export function attachmentWrappedKeyAad(messageId: string, uploadId: string): Uint8Array {
  return encoder.encode(serializeAttachmentWrappedKeyAad(messageId, uploadId));
}

export function attachmentChunkAad(
  uploadId: string,
  messageId: string,
  index: number,
  chunkCount: number,
  plaintextSize: number,
): Uint8Array {
  return encoder.encode(serializeAttachmentChunkAad(
    uploadId,
    messageId,
    index,
    chunkCount,
    plaintextSize,
  ));
}

export function attachmentChunkCount(plaintextSize: number): number {
  if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0 || plaintextSize > MAX_FILE_SIZE) {
    throw new Error('添付ファイルのサイズが許容範囲外です');
  }
  return Math.max(1, Math.ceil(plaintextSize / ATTACHMENT_PLAINTEXT_CHUNK_BYTES));
}

export function attachmentPlaintextChunkSize(plaintextSize: number, index: number): number {
  const chunkCount = attachmentChunkCount(plaintextSize);
  if (!Number.isSafeInteger(index) || index < 0 || index >= chunkCount) {
    throw new Error('添付チャンク番号が不正です');
  }
  const offset = index * ATTACHMENT_PLAINTEXT_CHUNK_BYTES;
  return Math.min(ATTACHMENT_PLAINTEXT_CHUNK_BYTES, Math.max(0, plaintextSize - offset));
}

export function attachmentCiphertextChunkSize(plaintextSize: number, index: number): number {
  return attachmentPlaintextChunkSize(plaintextSize, index) + ATTACHMENT_GCM_TAG_BYTES;
}

export function attachmentChunkNonce(prefix: Uint8Array, index: number): Uint8Array {
  if (prefix.byteLength !== ATTACHMENT_NONCE_PREFIX_BYTES) throw new Error('ファイル情報の形式が不正です');
  if (!Number.isSafeInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new Error('ファイルの分割情報が不正です');
  }
  const nonce = new Uint8Array(12);
  nonce.set(prefix, 0);
  new DataView(nonce.buffer).setUint32(8, index, false);
  return nonce;
}

/**
 * Reservation creation needs filenameEnc before uploadId exists. This helper
 * keeps the short-lived raw key alive only until the reservation is created,
 * then wraps and zeroes it in the caller's finally block.
 */
export async function prepareAttachmentFileKey(filename: string, messageId: string): Promise<{
  rawFileKey: Uint8Array;
  fileKey: CryptoKey;
  filenameEnc: string;
  noncePrefix: Uint8Array;
}> {
  const rawFileKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    const fileKey = await importAttachmentFileKey(rawFileKey);
    const filenameEnc = await encryptPacked(
      fileKey,
      encoder.encode(filename),
      attachmentFilenameAad(messageId),
    );
    return {
      rawFileKey,
      fileKey,
      filenameEnc,
      noncePrefix: crypto.getRandomValues(new Uint8Array(ATTACHMENT_NONCE_PREFIX_BYTES)),
    };
  } catch (error) {
    rawFileKey.fill(0);
    throw error;
  }
}

export async function wrapPreparedAttachmentFileKey(
  rawFileKey: Uint8Array,
  channelKey: CryptoKey,
  messageId: string,
  uploadId: string,
): Promise<string> {
  if (rawFileKey.byteLength !== 32) throw new Error('添付ファイル鍵が不正です');
  return encryptPacked(channelKey, rawFileKey, attachmentWrappedKeyAad(messageId, uploadId));
}

/** Seal ambiguous reservation-attempt material without retaining raw key bytes. */
export async function sealPreparedAttachmentFileKey(
  rawFileKey: Uint8Array,
  channelKey: CryptoKey,
  messageId: string,
  idempotencyKey: string,
): Promise<string> {
  if (rawFileKey.byteLength !== 32) throw new Error('添付ファイル鍵が不正です');
  return encryptPacked(channelKey, rawFileKey, preparedKeyAad(messageId, idempotencyKey));
}

/** Rewrap a sealed attempt key once the stable server upload id is known. */
export async function wrapSealedAttachmentFileKey(
  sealedFileKey: string,
  channelKey: CryptoKey,
  messageId: string,
  idempotencyKey: string,
  uploadId: string,
): Promise<string> {
  const raw = await decryptPacked(channelKey, sealedFileKey, preparedKeyAad(messageId, idempotencyKey));
  try {
    return await wrapPreparedAttachmentFileKey(raw, channelKey, messageId, uploadId);
  } finally {
    raw.fill(0);
  }
}

export async function encryptAttachmentChunk(
  plaintext: ArrayBuffer,
  fileKey: CryptoKey,
  noncePrefix: Uint8Array,
  uploadId: string,
  messageId: string,
  index: number,
  chunkCount: number,
  plaintextSize: number,
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: ownedArrayBuffer(attachmentChunkNonce(noncePrefix, index)),
    additionalData: ownedArrayBuffer(attachmentChunkAad(uploadId, messageId, index, chunkCount, plaintextSize)),
    tagLength: 128,
  }, fileKey, plaintext);
}

export async function decryptAttachmentChunk(
  ciphertext: ArrayBuffer,
  fileKey: CryptoKey,
  manifest: ValidatedAttachmentManifest,
  index: number,
): Promise<ArrayBuffer> {
  if (ciphertext.byteLength !== attachmentCiphertextChunkSize(manifest.plaintextSize, index)) {
    throw new Error('添付チャンクのサイズがmanifestと一致しません');
  }
  return crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: ownedArrayBuffer(attachmentChunkNonce(manifest.noncePrefix, index)),
    additionalData: ownedArrayBuffer(attachmentChunkAad(
      manifest.uploadId,
      manifest.messageId,
      index,
      manifest.chunkCount,
      manifest.plaintextSize,
    )),
    tagLength: 128,
  }, fileKey, ciphertext);
}

export async function unwrapAttachmentFileKey(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
): Promise<CryptoKey> {
  const envelope = await verifyAttachmentMetadata(message, attachment);
  const manifest = validateAttachmentManifest(attachment, envelope.messageId);
  const channelKey = await getChannelKeyForVersion(message.channelId, message.keyVersion);
  if (!channelKey) throw new Error('このチャンネルは現在ファイルを送信できません');
  const raw = await decryptPacked(
    channelKey,
    attachment.wrappedKey,
    attachmentWrappedKeyAad(manifest.messageId, manifest.uploadId),
  );
  try {
    if (raw.byteLength !== 32) throw new Error('添付ファイル鍵が不正です');
    return importAttachmentFileKey(raw);
  } finally {
    raw.fill(0);
  }
}

export async function decryptAttachmentFilename(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
): Promise<string> {
  validateAttachmentManifest(attachment, message.id);
  const fileKey = await unwrapAttachmentFileKey(message, attachment);
  const plaintext = await decryptPacked(fileKey, attachment.filenameEnc, attachmentFilenameAad(message.id));
  try {
    const filename = decoder.decode(plaintext);
    return sanitizeAttachmentFilename(filename);
  } finally {
    plaintext.fill(0);
  }
}

/** Build the exact signed metadata and reject legacy/mismatched DTOs. */
export function buildSignedAttachmentEnvelope(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
): SignedAttachmentEnvelope {
  const manifest = validateAttachmentManifest(attachment, message.id);
  if (
    !attachment.channelId
    || attachment.channelId !== message.channelId
    || !Number.isSafeInteger(attachment.keyVersion)
    || attachment.keyVersion === null
    || attachment.keyVersion <= 0
    || attachment.keyVersion !== message.keyVersion
    || !attachment.deviceId
    || !attachment.signature
    || normalizeAttachmentMimeType(attachment.mimeType) !== attachment.mimeType
  ) {
    throw new Error('ファイル情報が欠落しているか、メッセージと一致しません');
  }
  const filenamePacked = decodeCanonicalBase64(attachment.filenameEnc);
  const wrappedKeyPacked = decodeCanonicalBase64(attachment.wrappedKey, 60);
  decodeCanonicalBase64(attachment.signature, 64);
  if (filenamePacked.byteLength < 28 || filenamePacked.byteLength > 8192 || wrappedKeyPacked.byteLength !== 60) {
    throw new Error('ファイル情報の形式が不正です');
  }
  return {
    type: 'attachment',
    uploadId: manifest.uploadId,
    messageId: message.id,
    channelId: message.channelId,
    authorId: message.authorId,
    deviceId: attachment.deviceId,
    keyVersion: attachment.keyVersion,
    filenameEnc: attachment.filenameEnc,
    mimeType: attachment.mimeType,
    wrappedKey: attachment.wrappedKey,
    noncePrefix: attachment.cryptoManifest.noncePrefix,
    plaintextSize: manifest.plaintextSize,
    chunkCount: manifest.chunkCount,
  };
}

/** Verify uploader identity before any attachment plaintext is decrypted or saved. */
export async function verifyAttachmentMetadata(
  message: Pick<Message, 'id' | 'channelId' | 'authorId' | 'keyVersion'>,
  attachment: Attachment,
): Promise<SignedAttachmentEnvelope> {
  const envelope = buildSignedAttachmentEnvelope(message, attachment);
  let directoryEntry = await getDeviceDirectory(message.channelId, envelope.deviceId, false);
  let identity = directoryEntry?.userId === envelope.authorId ? directoryEntry.identityKey : undefined;
  if (!identity) {
    directoryEntry = await getDeviceDirectory(message.channelId, envelope.deviceId, true);
    identity = directoryEntry?.userId === envelope.authorId ? directoryEntry.identityKey : undefined;
  }
  if (!identity || !attachment.signature) throw new Error('ファイルの送信元を確認できません');
  if (!await verifyAttachmentSignature(envelope, attachment.signature, identity)) {
    throw new Error('ファイルの内容を検証できませんでした');
  }
  return envelope;
}

export function clearAttachmentVerificationCache(): void {
  directoryCacheGeneration += 1;
  directoryCache.clear();
  directoryPromises.clear();
}

export function validateAttachmentManifest(
  attachment: Attachment,
  expectedMessageId = attachment.messageId,
): ValidatedAttachmentManifest {
  const manifest = attachment.cryptoManifest;
  const plaintextSize = manifest?.plaintextSize;
  if (
    !manifest
    || manifest.version !== 1
    || manifest.algorithm !== 'AES-256-GCM'
    || manifest.nonceStrategy !== 'prefix-counter-be32'
    || manifest.aadVersion !== 1
    || manifest.aadFormat !== ATTACHMENT_CHUNK_AAD_FORMAT
    || manifest.messageId !== attachment.messageId
    || manifest.messageId !== expectedMessageId
    || manifest.uploadId.length === 0
    || manifest.chunkPlaintextBytes !== ATTACHMENT_PLAINTEXT_CHUNK_BYTES
    || manifest.authenticationTagBytes !== ATTACHMENT_GCM_TAG_BYTES
    || !Number.isSafeInteger(plaintextSize)
    || plaintextSize < 0
    || plaintextSize > MAX_FILE_SIZE
  ) {
    throw new Error('対応していないファイル形式です');
  }

  const expectedChunkCount = attachmentChunkCount(plaintextSize);
  const expectedCiphertextSize = plaintextSize + expectedChunkCount * ATTACHMENT_GCM_TAG_BYTES;
  if (
    manifest.chunkCount !== expectedChunkCount
    || attachment.chunkCount !== expectedChunkCount
    || attachment.plaintextSizeBytes !== plaintextSize
    || attachment.sizeBytes !== expectedCiphertextSize
    || attachment.ciphertextSizeBytes !== expectedCiphertextSize
    || attachment.downloadPolicy !== 'attachment-only'
  ) {
    throw new Error('ファイルサイズの情報が一致しません');
  }

  const noncePrefix = decodeCanonicalBase64(manifest.noncePrefix, ATTACHMENT_NONCE_PREFIX_BYTES);
  if (attachment.contentNonce !== manifest.noncePrefix) {
    throw new Error('ファイル情報が一致しません');
  }
  return {
    uploadId: manifest.uploadId,
    messageId: manifest.messageId,
    chunkCount: expectedChunkCount,
    plaintextSize,
    noncePrefix,
  };
}

export function sanitizeAttachmentFilename(filename: string): string {
  const sanitized = filename
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '_')
    .replace(/^\.+$/, '_')
    .trim()
    .slice(0, 240);
  return sanitized || 'attachment';
}

const DANGEROUS_ATTACHMENT_EXTENSIONS = new Set([
  'exe', 'com', 'bat', 'cmd', 'ps1', 'sh', 'js', 'mjs', 'cjs', 'vbs', 'msi',
  'scr', 'dll', 'hta', 'html', 'htm', 'svg', 'xml', 'xhtml', 'pdf', 'docm',
  'xlsm', 'pptm', 'jar', 'apk', 'app', 'dmg', 'iso', 'php', 'wasm', 'zip',
  '7z', 'rar', 'gz', 'bz2', 'xz', 'tar', 'lnk', 'reg', 'cpl', 'gadget', 'wsf',
  'wsh', 'sct', 'chm', 'inf', 'pif', 'vb', 'vbe', 'jse', 'doc', 'xls', 'ppt',
]);

/** Treat executable, active-content, macro, and archive names as dangerous. */
export function isDangerousAttachmentFilename(filename: string): boolean {
  const normalized = filename.normalize('NFKC').trim().replace(/[. ]+$/g, '').toLowerCase();
  const segments = normalized.split('.');
  if (segments.length < 2) return false;
  return segments.slice(1).some((extension) => {
    const token = extension.split(/[^a-z0-9]/, 1)[0];
    return DANGEROUS_ATTACHMENT_EXTENSIONS.has(extension) || DANGEROUS_ATTACHMENT_EXTENSIONS.has(token);
  });
}

export function normalizeAttachmentMimeType(mimeType: string): string {
  const normalized = mimeType.trim().toLowerCase();
  return /^[\w.+-]+\/[\w.+-]+$/.test(normalized) ? normalized : 'application/octet-stream';
}

export function encodeCanonicalBase64(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function decodeCanonicalBase64(value: string, expectedBytes?: number): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('データの形式が不正です');
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error('データの形式が不正です');
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if ((expectedBytes !== undefined && bytes.byteLength !== expectedBytes) || encodeCanonicalBase64(bytes) !== value) {
    throw new Error('正しい形式のデータではありません');
  }
  return bytes;
}

async function importAttachmentFileKey(raw: Uint8Array): Promise<CryptoKey> {
  const ownedRaw = ownedArrayBuffer(raw);
  try {
    return await crypto.subtle.importKey(
      'raw',
      ownedRaw,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    new Uint8Array(ownedRaw).fill(0);
  }
}

async function encryptPacked(key: CryptoKey, plaintext: Uint8Array, additionalData: Uint8Array): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ownedPlaintext = ownedArrayBuffer(plaintext);
  let ciphertext: Uint8Array;
  try {
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: ownedArrayBuffer(nonce),
      additionalData: ownedArrayBuffer(additionalData),
      tagLength: 128,
    }, key, ownedPlaintext));
  } finally {
    new Uint8Array(ownedPlaintext).fill(0);
  }
  const packed = new Uint8Array(nonce.byteLength + ciphertext.byteLength);
  packed.set(nonce, 0);
  packed.set(ciphertext, nonce.byteLength);
  return encodeCanonicalBase64(packed);
}

async function decryptPacked(key: CryptoKey, packedBase64: string, additionalData: Uint8Array): Promise<Uint8Array> {
  const packed = decodeCanonicalBase64(packedBase64);
  if (packed.byteLength < 12 + ATTACHMENT_GCM_TAG_BYTES) throw new Error('暗号化添付メタデータが短すぎます');
  const plaintext = await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: ownedArrayBuffer(packed.subarray(0, 12)),
    additionalData: ownedArrayBuffer(additionalData),
    tagLength: 128,
  }, key, ownedArrayBuffer(packed.subarray(12)));
  return new Uint8Array(plaintext);
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function preparedKeyAad(messageId: string, idempotencyKey: string): Uint8Array {
  return encoder.encode(`alparts-attachment-prepared-key-v1\0${messageId}\0${idempotencyKey}`);
}

async function getDeviceDirectory(
  channelId: string,
  deviceId: string,
  forceRefresh: boolean,
): Promise<DeviceDirectoryEntry | null> {
  const cacheKey = `${channelId}:${deviceId}`;
  const now = Date.now();
  const cached = directoryCache.get(cacheKey);
  if (!forceRefresh && cached && cached.expiresAt > now) return cached.entry;
  if (forceRefresh) directoryCache.delete(cacheKey);
  const inFlight = directoryPromises.get(cacheKey);
  if (inFlight) return inFlight;
  if (directoryPromises.size >= DIRECTORY_CACHE_LIMIT) throw new Error('DEVICE_DIRECTORY_CAPACITY');
  const generation = directoryCacheGeneration;
  const request = api.getChannelDeviceDirectory(channelId, [deviceId]).then((entries) => {
    const entry = entries.find((candidate) => candidate.deviceId === deviceId) ?? null;
    if (generation === directoryCacheGeneration) {
      directoryCache.delete(cacheKey);
      directoryCache.set(cacheKey, { entry, expiresAt: Date.now() + DIRECTORY_CACHE_TTL_MS });
      while (directoryCache.size > DIRECTORY_CACHE_LIMIT) {
        const oldest = directoryCache.keys().next().value as string | undefined;
        if (!oldest) break;
        directoryCache.delete(oldest);
      }
    }
    return entry;
  }).finally(() => {
    if (directoryPromises.get(cacheKey) === request) directoryPromises.delete(cacheKey);
  });
  directoryPromises.set(cacheKey, request);
  return request;
}
