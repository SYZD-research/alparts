type ErrorLike = { name?: unknown; code?: unknown };

export function logError(event: string, error: unknown): void {
  const value = (typeof error === 'object' && error !== null ? error : {}) as ErrorLike;
  console.error(JSON.stringify({
    level: 'error',
    event,
    errorName: typeof value.name === 'string' ? value.name : 'Error',
    errorCode: typeof value.code === 'string' ? value.code : undefined,
  }));
}

export function logInfo(event: string, details: Record<string, string | number | boolean> = {}): void {
  console.log(JSON.stringify({ level: 'info', event, ...details }));
}
