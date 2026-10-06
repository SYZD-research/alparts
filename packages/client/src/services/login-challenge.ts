import { t } from '../i18n';
export function solveLoginChallenge(
  challenge: unknown,
  signal?: AbortSignal | null,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./login-challenge.worker.ts', import.meta.url), {
      type: 'module',
    });
    const finish = (proof?: string) => {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
      worker.terminate();
      if (proof) resolve(proof);
      else reject(new Error(t('ログインできませんでした。時間をおいてもう一度お試しください。')));
    };
    const abort = () => finish();
    const timeout = setTimeout(abort, 90_000);
    worker.onmessage = (event: MessageEvent<unknown>) =>
      finish(typeof event.data === 'string' ? event.data : undefined);
    worker.onerror = () => finish();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    else worker.postMessage(challenge);
  });
}
