import { Router } from 'express';
import { z } from 'zod';
import * as deviceService from '../services/device.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';

const router = Router();

const registerSchema = z.object({
  name: z.string().min(1).max(100),
  identityKey: z.string().min(1), // RSA public key PEM
});

router.post('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const body = registerSchema.parse(req.body);
    const device = await deviceService.registerDevice(req.userId!, body.name, body.identityKey);
    res.status(201).json(device);
  } catch (err: any) {
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const devices = await deviceService.getUserDevices(req.userId!);
    res.json(devices);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.delete('/:id', authMiddleware, async (req: AuthRequest, res) => {
  try {
    await deviceService.revokeDevice(req.params.id, req.userId!);
    res.json({ success: true });
  } catch (err: any) {
    if (err.message === 'DEVICE_NOT_FOUND') {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Device not found', statusCode: 404 });
      return;
    }
    if (err.message === 'NOT_AUTHORIZED') {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Not authorized', statusCode: 403 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
