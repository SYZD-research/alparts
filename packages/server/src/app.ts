import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import { fileURLToPath } from 'node:url';
import { config } from './config/index.js';
import { setupWebSocket } from './websocket/index.js';
import authRoutes from './routes/auth.js';
import workspaceRoutes from './routes/workspaces.js';
import channelRoutes from './routes/channels.js';
import messageRoutes from './routes/messages.js';
import deviceRoutes from './routes/devices.js';
import fileRoutes from './routes/files.js';
import keyRoutes from './routes/keys.js';
import roleRoutes from './routes/roles.js';
import invitationRoutes from './routes/invitations.js';
import dmRoutes from './routes/dms.js';
import userStateRoutes from './routes/user-state.js';
import auditLogRoutes from './routes/audit-logs.js';
import permissionOverrideRoutes from './routes/permission-overrides.js';
import { enforceBrowserOrigin } from './middleware/origin.js';
import { rateLimit } from './middleware/rate-limit.js';
import { logError } from './security/logger.js';
import { checkDb } from './db/index.js';
import { checkObjectStorage } from './services/object-storage.js';
import { requestContext } from './middleware/request-context.js';
import { checkAuditCheckpoint } from './middleware/audit.js';
import { reserveJsonBody } from './middleware/body-admission.js';

export function createApp() {
  const app = express();
  const httpServer = createServer(app);
  httpServer.headersTimeout = 15_000;
  httpServer.requestTimeout = 120_000;
  httpServer.keepAliveTimeout = 5_000;
  httpServer.maxHeadersCount = 100;
  httpServer.maxRequestsPerSocket = 1_000;
  let shuttingDown = false;

  const io = new SocketServer(httpServer, {
    maxHttpBufferSize: 64 * 1024,
    perMessageDeflate: false,
    cors: {
      origin: config.cors.origins,
      methods: ['GET', 'POST'],
      credentials: true,
    },
  });

  // Middleware
  app.disable('x-powered-by');
  app.set('trust proxy', config.network.trustedProxies.length > 0 ? [...config.network.trustedProxies] : false);
  app.set('io', io);
  app.use(requestContext);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: config.isProduction ? ["'self'"] : ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        // The production SPA uses the same origin for both REST and Socket.IO.
        // Keeping this at self also prevents an injected script from opening an
        // arbitrary WebSocket as an exfiltration channel.
        connectSrc: config.isProduction ? ["'self'"] : ["'self'", 'ws:', 'wss:'],
        upgradeInsecureRequests: config.isProduction ? [] : null,
      },
    },
    hsts: config.isProduction ? { maxAge: 31_536_000, includeSubDomains: true, preload: true } : false,
    referrerPolicy: { policy: 'no-referrer' },
  }));
  // The top-level app may capture audio and select an output device. Explicitly
  // deny unrelated high-impact browser capabilities and prevent framed or
  // delegated origins from acquiring microphone access.
  app.use((_req, res, next) => {
    res.setHeader(
      'Permissions-Policy',
      'camera=(), display-capture=(), geolocation=(), microphone=(self), speaker-selection=(self)',
    );
    next();
  });
  app.use(cors({
    credentials: true,
    origin(origin, callback) {
      if (!origin || config.cors.origins.includes(origin)) callback(null, true);
      else callback(null, false);
    },
  }));
  // Reject credentialed cross-origin mutations before parsing their bodies.
  // CORS remains a browser response policy; this middleware is the actual
  // same-origin request boundary for cookie-authenticated state changes.
  app.use(enforceBrowserOrigin);
  // Apply the cheap shared request budget before any body parser allocates.
  app.use(rateLimit({ windowMs: 60_000, max: 300 }));
  // A full 400-device RSA channel-key fanout is roughly 240 KiB. Route-level
  // schemas still apply much tighter limits to every other field.
  app.use(reserveJsonBody(512 * 1024));
  app.use(express.json({ limit: '512kb', strict: true, type: 'application/json' }));
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.use((req, res, next) => {
    if (shuttingDown && !req.path.startsWith('/health')) {
      res.setHeader('Connection', 'close');
      res.status(503).json({ error: 'SHUTTING_DOWN', message: 'Server is shutting down', statusCode: 503 });
      return;
    }
    next();
  });

  // Separate probes let process supervisors distinguish a live process from a
  // node that is ready to accept durable writes.
  app.get('/health', (_req, res) => {
    res.json({ status: shuttingDown ? 'draining' : 'ok', timestamp: new Date().toISOString() });
  });
  app.get('/health/live', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/health/startup', (_req, res) => {
    res.status(shuttingDown ? 503 : 200).json({ status: shuttingDown ? 'draining' : 'ok' });
  });
  app.get('/health/ready', async (_req, res) => {
    if (shuttingDown) {
      res.status(503).json({ status: 'draining' });
      return;
    }
    try {
      await Promise.all([checkDb(), checkObjectStorage(), checkAuditCheckpoint()]);
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'unavailable' });
    }
  });

  // API Routes
  app.use('/api/auth', authRoutes);
  app.use('/api/workspaces', workspaceRoutes);
  app.use('/api', channelRoutes);
  app.use('/api', messageRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/files', fileRoutes);
  app.use('/api', keyRoutes);
  app.use('/api', roleRoutes);
  app.use('/api', invitationRoutes);
  app.use('/api', dmRoutes);
  app.use('/api', userStateRoutes);
  app.use('/api', auditLogRoutes);
  app.use('/api', permissionOverrideRoutes);

  // WebSocket
  setupWebSocket(io);

  if (config.isProduction) {
    const clientDist = fileURLToPath(new URL('../../client/dist/', import.meta.url));
    app.use(express.static(clientDist, {
      index: false,
      fallthrough: true,
      setHeaders(res, filename) {
        if (filename.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
        else res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      },
    }));
    app.get(/^(?!\/api(?:\/|$)).*/, (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.sendFile('index.html', { root: clientDist });
    });
  }

  // Error handler
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err?.type === 'entity.parse.failed' || err?.type === 'request.size.invalid') {
      res.status(400).json({ error: 'INVALID_JSON', message: 'Invalid JSON request body', statusCode: 400 });
      return;
    }
    if (err?.type === 'entity.too.large' || err?.status === 413) {
      res.status(413).json({ error: 'BODY_TOO_LARGE', message: 'Request body is too large', statusCode: 413 });
      return;
    }
    logError('http.unhandled', err);
    if (res.headersSent) return;
    res.status(500).json({ error: 'INTERNAL', message: 'Internal server error', statusCode: 500 });
  });

  return {
    app,
    httpServer,
    io,
    beginShutdown() {
      shuttingDown = true;
    },
  };
}
