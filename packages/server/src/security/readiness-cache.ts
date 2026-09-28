/** Share both successful and failed checks, including in-flight work. */
export function createReadinessCheck(check: () => Promise<void>, ttlMs = 2_000) {
  let pending: Promise<boolean> | undefined;
  let checkedAt = -Infinity;
  let ready = false;
  return (): Promise<boolean> => {
    if (pending) return pending;
    if (Date.now() - checkedAt < ttlMs) return Promise.resolve(ready);
    pending = Promise.resolve().then(check).then(() => true, () => false).then((result) => {
      ready = result;
      checkedAt = Date.now();
      return result;
    }).finally(() => { pending = undefined; });
    return pending;
  };
}
