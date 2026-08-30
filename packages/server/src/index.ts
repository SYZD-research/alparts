import { createApp } from './app.js';
import { config } from './config/index.js';
import { logError, logInfo } from './security/logger.js';
import { cleanupExpiredUploads } from './services/file.service.js';
import { flushAuditCheckpoint, verifyAuditChain } from './middleware/audit.js';
import { checkDatabaseSchema, closeDb } from './db/index.js';
import { closePasswordWorkers } from './security/password-work.js';

const migrationCount = await checkDatabaseSchema();
logInfo('database.schema_verified', { migrations: migrationCount });

const auditState = await verifyAuditChain();
if (!auditState.valid) throw new Error('Audit log integrity verification failed');
logInfo('audit.verified', { entries: auditState.checked, checkpoint: auditState.checkpoint });

const { httpServer, io, beginShutdown } = createApp();
httpServer.listen(config.port, config.bindHost, () => logInfo('server.started', {
  host: config.bindHost,
  port: config.port,
  environment: config.nodeEnv,
}));

let uploadCleanupRunning = false;
const uploadCleanup = setInterval(() => {
  if (uploadCleanupRunning) {
    logInfo('attachments.cleanup_skipped', { outcome: 'busy' });
    return;
  }
  uploadCleanupRunning = true;
  void cleanupExpiredUploads()
    .then((removed) => logInfo('attachments.cleanup_complete', { removed, outcome: 'success' }))
    .catch((error) => logError('attachments.cleanup', error))
    .finally(() => { uploadCleanupRunning = false; });
}, 15 * 60 * 1000);
uploadCleanup.unref();

let shutdownPromise: Promise<void> | null = null;
function shutdown(signal: string): Promise<void> {
  if (shutdownPromise) return shutdownPromise;
  shutdownPromise = (async () => {
    logInfo('server.shutdown_started', { signal });
    beginShutdown();
    clearInterval(uploadCleanup);
    io.disconnectSockets(true);

    const forceClose = setTimeout(() => {
      httpServer.closeAllConnections();
    }, 25_000);
    forceClose.unref();
    await new Promise<void>((resolve) => {
      if (!httpServer.listening) resolve();
      else httpServer.close(() => resolve());
    });
    clearTimeout(forceClose);
    let auditFlushError: unknown;
    try {
      await flushAuditCheckpoint();
    } catch (error) {
      auditFlushError = error;
    }
    await closePasswordWorkers();
    await closeDb();
    if (auditFlushError) throw auditFlushError;
    logInfo('server.shutdown_complete');
  })().catch((error) => {
    logError('server.shutdown_failed', error);
    process.exitCode = 1;
  });
  return shutdownPromise;
}

process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
process.once('SIGINT', () => { void shutdown('SIGINT'); });

function fatal(kind: 'uncaughtException' | 'unhandledRejection', error: unknown): void {
  logError(`process.${kind}`, error);
  const forcedExit = setTimeout(() => process.exit(1), 30_000);
  forcedExit.unref();
  void shutdown(kind).finally(() => {
    clearTimeout(forcedExit);
    process.exit(1);
  });
}

process.once('uncaughtException', (error) => fatal('uncaughtException', error));
process.once('unhandledRejection', (error) => fatal('unhandledRejection', error));
