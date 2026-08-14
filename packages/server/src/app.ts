import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import { config } from './config/index.js';
import { setupWebSocket } from './websocket/index.js';
import authRoutes from './routes/auth.js';
import workspaceRoutes from './routes/workspaces.js';
import channelRoutes from './routes/channels.js';
import messageRoutes from './routes/messages.js';
import deviceRoutes from './routes/devices.js';
import fileRoutes from './routes/files.js';

export function createApp() {
  const app = express();
  const httpServer = createServer(app);

  const io = new SocketServer(httpServer, {
    cors: {
      origin: config.cors.origin,
      methods: ['GET', 'POST'],
    },
  });

  // Middleware
  app.use(helmet());
  app.use(cors({ origin: config.cors.origin }));
  app.use(express.json({ limit: '10mb' }));

  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // API Routes
  app.use('/api/auth', authRoutes);
  app.use('/api/workspaces', workspaceRoutes);
  app.use('/api', channelRoutes);
  app.use('/api', messageRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/files', fileRoutes);

  // WebSocket
  setupWebSocket(io);

  // Error handler
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  });

  return { app, httpServer, io };
}
