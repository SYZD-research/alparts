import { acquireRuntimeLease } from './security/runtime-lease.js';
import { createApp } from './app.js';
import { config } from './config/index.js';
import { logError, logInfo, logWarning } from './security/logger.js';
import { emailDelivery } from './services/email.service.js';
import { cleanupExpiredUploads } from './services/file.service.js';
import { flushAuditCheckpoint, verifyAuditChain } from './middleware/audit.js';
import { checkDatabaseSchema, closeDb } from './db/index.js';
import { closePasswordWorkers } from './security/password-work.js';
import { resetPresenceAfterStartup } from './websocket/presence.handler.js';

const runtime = await acquireRuntimeLease();
const migrationCount = await checkDatabaseSchema();
logInfo('database.schema_verified', { migrations: migrationCount });

const auditState = await verifyAuditChain();
if (!auditState.valid) throw new Error('Audit log integrity verification failed');
logInfo('audit.verified', { entries: auditState.checked, checkpoint: auditState.checkpoint });
await resetPresenceAfterStartup();
if (config.email.verification === 'required' && emailDelivery() === 'unavailable') {
  // Existing users keep working; only new registrations wait for SMTP.
  logWarning('registration.unavailable', { reason: 'Set SMTP_HOST and SMTP_FROM, or EMAIL_VERIFICATION=disabled' });
}

const { httpServer, io, beginShutdown } = createApp();
httpServer.listen(config.port, config.bindHost, () => logInfo('server.started', {
  host: config.bindHost,
  port: config.port,
  environment: config.nodeEnv,
  trustedProxies: config.network.trustedProxies.join(',') || 'none',
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
    await runtime.close();
    if (auditFlushError) throw auditFlushError;
    logInfo('server.shutdown_complete');
  })().catch((error) => {
    logError('server.shutdown_failed', error);
    process.exitCode = 1;
  });
  return shutdownPromise;
}

// Without the lease this process must not keep serving; a stuck checkpoint
// flush must not leave it alive, so apply the same forced-exit deadline.
runtime.onLost(() => { terminate('runtime-lease-lost'); });

process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
process.once('SIGINT', () => { void shutdown('SIGINT'); });

function terminate(reason: string): void {
  const forcedExit = setTimeout(() => process.exit(1), 30_000);
  forcedExit.unref();
  void shutdown(reason).finally(() => {
    clearTimeout(forcedExit);
    process.exit(1);
  });
}

function fatal(kind: 'uncaughtException' | 'unhandledRejection', error: unknown): void {
  logError(`process.${kind}`, error);
  terminate(kind);
}

process.once('uncaughtException', (error) => fatal('uncaughtException', error));
process.once('unhandledRejection', (error) => fatal('unhandledRejection', error));
