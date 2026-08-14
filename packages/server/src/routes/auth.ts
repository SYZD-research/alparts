import { Router } from 'express';
import { z } from 'zod';
import * as authService from '../services/auth.service.js';
import { authMiddleware, AuthRequest } from '../middleware/auth.js';

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  displayName: z.string().min(1).max(100),
  inviteToken: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

router.post('/register', async (req, res) => {
  try {
    const body = registerSchema.parse(req.body);
    const user = await authService.register(body.email, body.password, body.displayName);
    res.status(201).json(user);
  } catch (err: any) {
    if (err.message === 'EMAIL_EXISTS') {
      res.status(409).json({ error: 'CONFLICT', message: 'Email already registered', statusCode: 409 });
      return;
    }
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.post('/login', async (req, res) => {
  try {
    const body = loginSchema.parse(req.body);
    const result = await authService.login(body.email, body.password, req.body.deviceInfo);
    res.json(result);
  } catch (err: any) {
    if (err.message === 'INVALID_CREDENTIALS') {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid email or password', statusCode: 401 });
      return;
    }
    if (err.name === 'ZodError') {
      res.status(400).json({ error: 'VALIDATION', message: err.errors[0]?.message, statusCode: 400 });
      return;
    }
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.post('/logout', authMiddleware, async (req: AuthRequest, res) => {
  try {
    if (req.sessionId) {
      await authService.logout(req.sessionId);
    }
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

router.get('/me', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const user = await authService.getUserById(req.userId!);
    if (!user) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'User not found', statusCode: 404 });
      return;
    }
    res.json(user);
  } catch {
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  }
});

export default router;
