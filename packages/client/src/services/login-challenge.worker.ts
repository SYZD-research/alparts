import { sha256 } from '@noble/hashes/sha2.js';

self.onmessage = (event: MessageEvent<{ token: string; difficulty: number }>) => {
  const { token, difficulty } = event.data;
  if (typeof token !== 'string' || token.length > 1000 || difficulty !== 22) {
    self.postMessage(null);
    return;
  }
  const encoder = new TextEncoder();
  const deadline = Date.now() + 90_000;
  for (let nonce = 0; nonce < 0xffffffff; nonce++) {
    const hash = sha256(encoder.encode(`${token}:${nonce}`));
    if (hash[0] === 0 && hash[1] === 0 && hash[2] < 4) {
      self.postMessage(`${token}.${nonce}`);
      return;
    }
    if (nonce % 4096 === 0 && Date.now() >= deadline) break;
  }
  self.postMessage(null);
};
