import { AsyncLocalStorage } from 'node:async_hooks';

export interface LogContext {
  requestId: string;
  traceId: string;
  actorId?: string;
  tenantId?: string;
}

const storage = new AsyncLocalStorage<LogContext>();

export function runWithLogContext<T>(context: LogContext, operation: () => T): T {
  return storage.run(context, operation);
}

export function currentLogContext(): LogContext | undefined {
  return storage.getStore();
}

export function setLogActor(actorId: string): void {
  const context = storage.getStore();
  if (context) context.actorId = actorId;
}

export function setLogTenant(tenantId: string): void {
  const context = storage.getStore();
  if (context) context.tenantId = tenantId;
}
