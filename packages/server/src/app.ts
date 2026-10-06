import { consumeSocketRate, type AuthenticatedSocket } from './websocket/security.js';
import { requireRuntimeLease } from './security/runtime-lease.js';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import { fileURLToPath } from 'node:url';
import { config } from './config/index.js';
import { setupWebSocket } from './websocket/index.js';
import authRoutes from './routes/auth.js';
import recoveryRoutes from './routes/recovery.js';
import mlsRoutes from './routes/mls.js';
import directoryRoutes from './routes/directory.js';
import passkeyRoutes from './routes/passkeys.js';
import { sensitiveActionBoundary } from './middleware/step-up.js';
import workspaceRoutes from './routes/workspaces.js';
import channelRoutes from './routes/channels.js';
import messageRoutes from './routes/messages.js';
import forumRoutes from './routes/forum.js';
import deviceRoutes from './routes/devices.js';
import fileRoutes from './routes/files.js';
import keyRoutes from './routes/keys.js';
import roleRoutes from './routes/roles.js';
import invitationRoutes from './routes/invitations.js';
import dmRoutes from './routes/dms.js';
import userStateRoutes from './routes/user-state.js';
import auditLogRoutes from './routes/audit-logs.js';
import permissionOverrideRoutes from './routes/permission-overrides.js';
import profileRoutes from './routes/profiles.js';
import { enforceBrowserOrigin } from './middleware/origin.js';
import { rateLimit } from './middleware/rate-limit.js';
import { logError } from './security/logger.js';
import { checkDatabaseSchema, checkDb } from './db/index.js';
import { checkObjectStorage } from './services/object-storage.js';
import { requestContext } from './middleware/request-context.js';
import { checkAuditCheckpoint } from './middleware/audit.js';
import { reserveJsonBody } from './middleware/body-admission.js';
import { renderPrometheusMetrics } from './observability/metrics.js';
import { matchesSecret } from './security/cookies.js';
import { createReadinessCheck } from './security/readiness-cache.js';
import { reportUntrustedForwarding } from './security/client-address.js';

/**
 * Expected domain failures that individual routes do not translate. They are
 * fail-closed already; this keeps them from surfacing as retry-hostile 500s.
 */
const DOMAIN_ERROR_STATUS: Record<string, { status: number; message: string; retryAfter?: string }> = {
  DIRECTORY_CONFLICT: { status: 409, message: 'Device directory changed' },
  DIRECTORY_LIMIT: { status: 409, message: 'Device directory limit reached' },
  DEVICE_APPROVAL_REQUIRED: { status: 403, message: 'Device approval is required' },
  DEVICE_REQUIRED: { status: 428, message: 'A bound device is required' },
  DEVICE_CHALLENGE_CAPACITY: { status: 503, message: 'Device verification is temporarily busy', retryAfter: '5' },
  CHANNEL_NOT_FOUND: { status: 404, message: 'Channel not found' },
  NOT_AUTHORIZED: { status: 403, message: 'Not authorized' },
};

export function createApp() {
  if (!config.audit.checkpointPath || !config.audit.checkpointRequired) throw new Error('AUDIT_CHECKPOINT_REQUIRED');
  if (!config.audit.headObjectKey) throw new Error('AUDIT_HEAD_REQUIRED');
  const runtime = requireRuntimeLease();
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

  runtime.onLost(() => {
    shuttingDown = true;
    io.disconnectSockets(true);
    httpServer.closeAllConnections();
    httpServer.close();
  });
  runtime.onAccountDisabled((userId) => io.in(`user:${userId}`).disconnectSockets(true));
  io.engine.use((
    _req: import('node:http').IncomingMessage,
    _res: import('node:http').ServerResponse,
    next: (error?: Error) => void,
  ) => next(runtime.isAlive() ? undefined : new Error('SERVICE_UNAVAILABLE')));
  io.on('connection', (socket: AuthenticatedSocket) => {
    socket.use((_packet, next) => {
      if (!consumeSocketRate(socket, 'runtime-admission', 1200, 60_000)) {
        next(new Error('RATE_LIMITED'));
        return;
      }
      void runtime.check().then(() => next(), () => {
        socket.disconnect(true);
        next(new Error('SERVICE_UNAVAILABLE'));
      });
    });
  });

  // Middleware
  app.disable('x-powered-by');
  app.set('query parser', 'simple');
  app.set('trust proxy', config.network.trustedProxies.length > 0 ? [...config.network.trustedProxies] : false);
  app.set('io', io);
  app.use(requestContext);
  app.use((req, _res, next) => {
    reportUntrustedForwarding(req);
    next();
  });
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
        // Authenticated attachment previews are decrypted into short-lived
        // local object URLs. Network image origins remain disallowed.
        imgSrc: ["'self'", 'data:', 'blob:'],
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
  app.use((_req, res, next) => {
    void runtime.check().then(() => next(), () => {
      res.status(503).json({ error: 'SERVICE_UNAVAILABLE' });
    });
  });

  // Signed group proposals include up to 400 public packages and the Welcome.
  // Keep their bounded allowance separate from ordinary JSON requests.
  const groupBody = reserveJsonBody(2 * 1024 * 1024);
  const normalBody = reserveJsonBody(512 * 1024);
  const groupParser = express.json({ limit: '2mb', strict: true, type: 'application/json' });
  const normalParser = express.json({ limit: '512kb', strict: true, type: 'application/json' });
  app.use((req, res, next) => (/^\/api\/channels\/[^/]+\/mls\/epochs(?:\/fresh-start)?$/.test(req.path) ? groupBody : normalBody)(req, res, next));
  app.use((req, res, next) => (/^\/api\/channels\/[^/]+\/mls\/epochs(?:\/fresh-start)?$/.test(req.path) ? groupParser : normalParser)(req, res, next));
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
  const ready = createReadinessCheck(async () => {
    await Promise.all([checkDb(), checkDatabaseSchema(), checkObjectStorage(), checkAuditCheckpoint()]);
  });
  app.get('/health/ready', async (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (shuttingDown) {
      res.status(503).json({ status: 'draining' });
      return;
    }
    if (await ready()) {
      res.json({ status: 'ready' });
    } else {
      res.status(503).json({ status: 'unavailable' });
    }
  });
  if (config.observability.metricsEnabled) {
    app.get('/metrics', (req, res) => {
      const authorization = req.headers.authorization;
      const supplied = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
      if (!config.observability.metricsToken || !matchesSecret(supplied, config.observability.metricsToken)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        res.status(401).type('text/plain').send('Authentication required\n');
        return;
      }
      res.setHeader('Cache-Control', 'no-store');
      res.type('text/plain; version=0.0.4').send(renderPrometheusMetrics());
    });
  }

  // API Routes
  app.use('/api', sensitiveActionBoundary);
  app.use('/api/auth', passkeyRoutes);
  app.use('/api', directoryRoutes);
  app.use('/api', mlsRoutes);
  app.use('/api/recovery', recoveryRoutes);
  app.use('/api/auth', authRoutes);
  app.use('/api/workspaces', workspaceRoutes);
  app.use('/api', channelRoutes);
  app.use('/api', messageRoutes);
  app.use('/api', forumRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/files', fileRoutes);
  app.use('/api', keyRoutes);
  app.use('/api', roleRoutes);
  app.use('/api', invitationRoutes);
  app.use('/api', dmRoutes);
  app.use('/api', userStateRoutes);
  app.use('/api', auditLogRoutes);
  app.use('/api', permissionOverrideRoutes);
  app.use('/api', profileRoutes);

  // WebSocket
  setupWebSocket(io);
  io.use((_socket, next) => {
    void runtime.check().then(() => next(), () => next(new Error('SERVICE_UNAVAILABLE')));
  });

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
    if (err?.message === 'AUTH_CAPACITY') {
      res.setHeader('Retry-After', '5');
      res.status(503).json({ error: 'AUTH_CAPACITY', message: 'Authentication capacity is temporarily exhausted', statusCode: 503 });
      return;
    }
    if (err?.message === 'AUDIT_UNAVAILABLE') {
      res.setHeader('Retry-After', '30');
      res.status(503).json({ error: 'AUDIT_UNAVAILABLE', message: 'Authoritative writes are temporarily unavailable', statusCode: 503 });
      return;
    }
    if (typeof err?.message === 'string' && (
      err.message.endsWith('_INVARIANT_EXCEEDED')
      || err.message === 'AUTHORIZATION_INPUT_LIMIT_EXCEEDED'
    )) {
      res.setHeader('Retry-After', '30');
      res.status(503).json({ error: 'DATA_INVARIANT', message: 'A bounded data invariant requires operator attention', statusCode: 503 });
      return;
    }
    const domain = typeof err?.message === 'string' ? DOMAIN_ERROR_STATUS[err.message] : undefined;
    if (domain && !res.headersSent) {
      if (domain.retryAfter) res.setHeader('Retry-After', domain.retryAfter);
      res.status(domain.status).json({ error: err.message, message: domain.message, statusCode: domain.status });
      return;
    }
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
