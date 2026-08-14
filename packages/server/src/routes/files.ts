import { Router } from 'express';
import { z } from 'zod';
import * as fileService from '../services/file.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';

const router = Router();

const uploadSchema = z.object({
  messageId: z.string().uuid(),
  filename: z.string().min(1).max(255),
  mimeType: z.string(),
});

router.post('/upload-url', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = uploadSchema.parse(req.body);
    const { url, storageKey } = await fileService.getUploadUrl(body.messageId, body.filename, body.mimeType);
    res.json({ url, storageKey });
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.post('/save', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { messageId, filenameEnc, mimeType, sizeBytes, storageKey, encryptionKey, thumbnailKey } = req.body;
    if (!messageId || !filenameEnc || !mimeType || !sizeBytes || !storageKey || !encryptionKey) {
      res.status(400).json({ error: 'VALIDATION', message: 'Missing required fields', statusCode: 400 });
      return;
    }
    const attachment = await fileService.saveAttachment({
      messageId,
      filenameEnc,
      mimeType,
      sizeBytes,
      storageKey,
      encryptionKey,
      thumbnailKey,
    });
    res.status(201).json(attachment);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/:id/download', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const attachment = await fileService.getAttachmentById(req.params.id);
    if (!attachment) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Attachment not found', statusCode: 404 });
      return;
    }
    const url = await fileService.getDownloadUrl(attachment.storageKey);
    res.json({ url, encryptionKey: attachment.encryptionKey });
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
