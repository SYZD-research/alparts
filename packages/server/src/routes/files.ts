import { pipeline } from 'node:stream/promises';
import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import type { Server as SocketServer } from 'socket.io';
import { z } from 'zod';
import { MAX_FILE_SIZE } from '@alparts/shared';
import * as fileService from '../services/file.service.js';
import { keyWriteErrorDetails } from '../security/key-write-errors.js';
import { authMiddleware, type AuthRequest } from '../middleware/auth.js';
import { rateLimit, requestSource } from '../middleware/rate-limit.js';
import { rawRequestBody, reserveKnownLengthBody } from '../middleware/body-admission.js';

const router = Router();
const base64 = z.string().min(16).max(8192).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const id = z.string().uuid();
const chunkIndex = z.coerce.number().int().min(0).max(fileService.MAX_ATTACHMENT_CHUNKS - 1);
const uploadSchema = z.object({
  idempotencyKey: id,
  messageId: id,
  filenameEnc: base64,
  mimeType: z.string().trim().min(1).max(127).regex(/^[\w.+-]+\/[\w.+-]+$/),
}).strict();
const finalizeSchema = z.object({
  deviceId: id,
  keyVersion: z.number().int().min(1).max(1_000_000),
  signature: z.string().length(88).regex(/^[A-Za-z0-9+/]{86}==$/),
  chunkCount: z.number().int().min(1).max(fileService.MAX_ATTACHMENT_CHUNKS),
  wrappedKey: base64,
  cryptoManifest: z.object({
    version: z.literal(1),
    algorithm: z.literal('AES-256-GCM'),
    nonceStrategy: z.literal('prefix-counter-be32'),
    noncePrefix: z.string().length(12).regex(/^[A-Za-z0-9+/]{11}=$/),
    aadVersion: z.literal(1),
    plaintextSize: z.number().int().min(0).max(MAX_FILE_SIZE),
  }).strict(),
}).strict();

const reservationLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const chunkLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1_000,
  key: (req) => (req as AuthRequest).userId || requestSource(req),
});
const rawChunkParser = express.raw({
  type: 'application/octet-stream',
  limit: fileService.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES,
});
const reserveChunkBody = reserveKnownLengthBody(fileService.ATTACHMENT_CIPHERTEXT_CHUNK_BYTES);
const requireChunkContentType: RequestHandler = (req, res, next) => {
  if (!req.is('application/octet-stream')) {
    res.status(415).json({
      error: 'UNSUPPORTED_MEDIA_TYPE',
      message: 'Chunk Content-Type must be application/octet-stream',
      statusCode: 415,
    });
    return;
  }
  next();
};

const parseChunkBody: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  if (!req.is('application/octet-stream')) {
    res.status(415).json({
      error: 'UNSUPPORTED_MEDIA_TYPE',
      message: 'Chunk Content-Type must be application/octet-stream',
      statusCode: 415,
    });
    return;
  }
  rawChunkParser(req, res, (error?: any) => {
    if (error?.type === 'entity.too.large' || error?.status === 413) {
      res.status(413).json({ error: 'CHUNK_TOO_LARGE', message: 'Attachment chunk is too large', statusCode: 413 });
      return;
    }
    if (error) {
      next(error);
      return;
    }
    next();
  });
};

router.post('/uploads', authMiddleware, reservationLimit, async (req: AuthRequest, res) => {
  try {
    const body = uploadSchema.parse(req.body);
    const created = await fileService.createUpload(
      req.userId!,
      body.messageId,
      body.filenameEnc,
      body.mimeType,
      body.idempotencyKey,
    );
    res.status(created.reused ? 200 : 201).json(created);
  } catch (error) {
    if (sendFileError(error, res)) return;
    throw error;
  }
});

router.delete('/uploads/:uploadId', authMiddleware, async (req: AuthRequest, res) => {
  if (!id.safeParse(req.params.uploadId).success) {
    sendNotFound(res, 'Upload reservation not found');
    return;
  }
  try {
    res.json(await fileService.cancelUpload(req.params.uploadId, req.userId!));
  } catch (error) {
    if (sendFileError(error, res)) return;
    throw error;
  }
});

router.get('/uploads/:uploadId', authMiddleware, async (req: AuthRequest, res) => {
  if (!id.safeParse(req.params.uploadId).success) {
    sendNotFound(res, 'Upload reservation not found');
    return;
  }
  try {
    res.json(await fileService.getUploadStatus(req.params.uploadId, req.userId!));
  } catch (error) {
    if (sendFileError(error, res)) return;
    throw error;
  }
});

router.put(
  '/uploads/:uploadId/chunks/:index',
  authMiddleware,
  chunkLimit,
  requireChunkContentType,
  (req: AuthRequest, res, next) => {
    const parsedUploadId = id.safeParse(req.params.uploadId);
    const parsedIndex = chunkIndex.safeParse(req.params.index);
    if (!parsedUploadId.success) {
      sendNotFound(res, 'Upload reservation not found');
      return;
    }
    if (!parsedIndex.success) {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid attachment chunk', statusCode: 400 });
      return;
    }
    res.locals.uploadId = parsedUploadId.data;
    res.locals.chunkIndex = parsedIndex.data;
    next();
  },
  reserveChunkBody,
  async (req: AuthRequest, res, next) => {
    try {
      await fileService.preflightUploadChunk(
        res.locals.uploadId,
        req.userId!,
        res.locals.chunkIndex,
        res.locals.expectedBodyBytes,
      );
      next();
    } catch (error) {
      if (sendFileError(error, res)) return;
      next(error);
    }
  },
  parseChunkBody,
  async (req: AuthRequest, res) => {
    const chunk = rawRequestBody(req);
    if (!chunk || chunk.length !== res.locals.expectedBodyBytes) {
      res.status(400).json({ error: 'VALIDATION', message: 'Invalid attachment chunk', statusCode: 400 });
      return;
    }
    try {
      const saved = await fileService.storeUploadChunk(
        res.locals.uploadId,
        req.userId!,
        res.locals.chunkIndex,
        chunk,
      );
      res.status(saved.replaced ? 200 : 201).json(saved);
    } catch (error) {
      if (sendFileError(error, res)) return;
      throw error;
    }
  },
);

router.post('/uploads/:uploadId/finalize', authMiddleware, async (req: AuthRequest, res) => {
  if (!id.safeParse(req.params.uploadId).success) {
    sendNotFound(res, 'Upload reservation not found');
    return;
  }
  try {
    const body = finalizeSchema.parse(req.body);
    assertBoundDevice(req, body.deviceId);
    const result = await fileService.finalizeUpload(
      req.params.uploadId,
      req.userId!,
      body,
    );
    const io = req.app.get('io') as SocketServer | undefined;
    io?.to(`channel:${result.channelId}`).emit('attachment:created', result.attachment);
    res.status(201).json(result.attachment);
  } catch (error) {
    if (sendFileError(error, res)) return;
    throw error;
  }
});

router.get('/:id/chunks/:index', authMiddleware, async (req: AuthRequest, res) => {
  const parsedId = id.safeParse(req.params.id);
  const parsedIndex = chunkIndex.safeParse(req.params.index);
  if (!parsedId.success || !parsedIndex.success) {
    sendNotFound(res, 'Attachment not found');
    return;
  }
  try {
    const chunk = await fileService.getAuthorizedAttachmentChunk(parsedId.data, parsedIndex.data, req.userId!);
    res.status(200);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(chunk.sizeBytes));
    res.setHeader('Content-Disposition', 'attachment; filename="encrypted-attachment.bin"');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'");
    // The stream already stops at the stored length; this also refuses to
    // finish a response whose body and Content-Length disagree.
    res.strictContentLength = true;
    await pipeline(chunk.stream, res);
  } catch (error) {
    if (!res.headersSent && sendFileError(error, res)) return;
    throw error;
  }
});

router.get('/:id', authMiddleware, async (req: AuthRequest, res) => {
  if (!id.safeParse(req.params.id).success) {
    sendNotFound(res, 'Attachment not found');
    return;
  }
  try {
    res.json(await fileService.getAuthorizedAttachmentMetadata(req.params.id, req.userId!));
  } catch (error) {
    if (sendFileError(error, res)) return;
    throw error;
  }
});

function sendFileError(error: unknown, res: Response): boolean {
  const name = error instanceof Error ? error.name : '';
  const code = error instanceof Error ? error.message : '';
  if (name === 'ZodError') {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid attachment request', statusCode: 400 });
    return true;
  }
  if (code === 'ATTACHMENT_NOT_FOUND') {
    sendNotFound(res, 'Attachment not found');
    return true;
  }
  if (code === 'UPLOAD_NOT_FOUND' || code === 'MESSAGE_NOT_FOUND') {
    sendNotFound(res, code === 'MESSAGE_NOT_FOUND' ? 'Message not found' : 'Upload reservation not found');
    return true;
  }
  if (code === 'NOT_AUTHORIZED') {
    res.status(403).json({ error: 'FORBIDDEN', message: 'Attachment upload is not permitted', statusCode: 403 });
    return true;
  }
  if (code === 'STORAGE_QUOTA_EXCEEDED') {
    res.status(413).json({ error: code, message: 'Storage quota exceeded', statusCode: 413 });
    return true;
  }
  if (
    code === 'OBJECT_STORAGE_TIMEOUT'
    || code === 'OBJECT_STORAGE_BUSY'
    || code === 'UPLOAD_OPERATION_BUSY'
    || code === 'OBJECT_STORAGE_LIST_LIMIT'
    || code === 'OBJECT_STORAGE_LIST_INVALID_KEY'
    || code === 'OBJECT_STORAGE_INTEGRITY'
  ) {
    res.setHeader('Retry-After', '5');
    res.status(503).json({
      error: code,
      message: code === 'OBJECT_STORAGE_TIMEOUT'
        ? 'Object storage request timed out'
        : code === 'OBJECT_STORAGE_BUSY' || code === 'UPLOAD_OPERATION_BUSY'
          ? 'Object storage is at its concurrency limit'
          : code === 'OBJECT_STORAGE_INTEGRITY'
            ? 'Object storage stored different bytes than were sent'
            : 'Object storage returned an unsafe or excessive listing',
      statusCode: 503,
    });
    return true;
  }
  if (code === 'DOWNLOAD_LIMIT_REACHED') {
    res.status(429).json({ error: code, message: 'Too many concurrent downloads', statusCode: 429 });
    return true;
  }
  if (code === 'UPLOAD_ALREADY_COMPLETED') {
    res.status(409).json({ error: code, message: 'Upload reservation is already completed', statusCode: 409 });
    return true;
  }
  if (code === 'UPLOAD_EXPIRED') {
    res.status(410).json({ error: code, message: 'Upload reservation expired; retry with a new idempotency key', statusCode: 410 });
    return true;
  }
  if (code === 'PENDING_UPLOAD_USER_LIMIT_REACHED' || code === 'PENDING_UPLOAD_WORKSPACE_LIMIT_REACHED') {
    res.status(409).json({
      error: code,
      message: 'Cancel or complete an existing upload reservation before creating another',
      statusCode: 409,
    });
    return true;
  }
  if (code === 'IDEMPOTENCY_CONFLICT' || code === 'ATTACHMENT_LIMIT_EXCEEDED') {
    res.status(409).json({ error: code, message: code === 'IDEMPOTENCY_CONFLICT'
      ? 'Idempotency key was already used for a different attachment reservation'
      : `A message can have at most ${fileService.MAX_ATTACHMENTS_PER_MESSAGE} attachments`, statusCode: 409 });
    return true;
  }
  if (code === 'CHUNK_OBJECT_MISSING' || code === 'CHUNK_OBJECT_MISMATCH') {
    res.status(409).json({ error: code, message: 'One or more uploaded chunks must be uploaded again', statusCode: 409 });
    return true;
  }
  if (
    code === 'INVALID_CHUNK_SIZE'
    || code === 'INVALID_CHUNK_INDEX'
    || code === 'INVALID_CHUNK_COUNT'
    || code === 'INVALID_CHUNK_LAYOUT'
    || code === 'INVALID_CRYPTO_MANIFEST'
    || code === 'DEVICE_MISMATCH'
    || code === 'INVALID_DEVICE'
    || code === 'INVALID_KEY_VERSION'
    || code === 'KEY_ROTATION_REQUIRED'
    || code === 'KEY_VERSION_STALE'
    || code === 'INVALID_SIGNATURE'
  ) {
    res.status(400).json({ error: 'VALIDATION', message: 'Invalid attachment upload', statusCode: 400, ...keyWriteErrorDetails(error) });
    return true;
  }
  return false;
}

function assertBoundDevice(req: AuthRequest, deviceId: string): void {
  if (!req.deviceId || req.deviceId !== deviceId) throw new Error('DEVICE_MISMATCH');
}

function sendNotFound(res: Response, message: string): void {
  res.status(404).json({ error: 'NOT_FOUND', message, statusCode: 404 });
}

export default router;
