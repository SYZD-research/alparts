import { currentLogContext } from './log-context.js';

type ErrorLike = { name?: unknown; code?: unknown };

function base(level: 'info' | 'error', event: string) {
  const context = currentLogContext();
  return {
    timestamp: new Date().toISOString(),
    severity: level,
    level,
    component: event.split('.', 1)[0] || 'application',
    operation: event,
    event,
    ...(context ? {
      requestId: context.requestId,
      traceId: context.traceId,
      ...(context.actorId ? { actorId: context.actorId } : {}),
      ...(context.tenantId ? { tenantId: context.tenantId } : {}),
    } : {}),
  };
}

export function logError(event: string, error: unknown): void {
  const value = (typeof error === 'object' && error !== null ? error : {}) as ErrorLike;
  console.error(JSON.stringify({
    ...base('error', event),
    outcome: 'failure',
    errorName: typeof value.name === 'string' ? value.name : 'Error',
    errorCode: typeof value.code === 'string' ? value.code : undefined,
  }));
}

export function logInfo(event: string, details: Record<string, string | number | boolean> = {}): void {
  console.log(JSON.stringify({ ...base('info', event), ...details }));
}
