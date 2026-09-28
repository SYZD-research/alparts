import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { passwordPepper } from './password-pepper.js';

export const LOGIN_CHALLENGE_DIFFICULTY = 22;
const used = new Map<string, number>();
const lifetime = 120_000;
function mac(value: string) {
  return createHmac('sha256', passwordPepper())
    .update('alparts.login.challenge.v1\0')
    .update(value)
    .digest('base64url');
}
export function issueLoginChallenge(binding: string, now = Date.now()) {
  const payload = Buffer.from(
    JSON.stringify({
      binding,
      expires: now + lifetime,
      nonce: randomBytes(24).toString('base64url'),
    }),
  ).toString('base64url');
  return { token: `${payload}.${mac(payload)}`, difficulty: LOGIN_CHALLENGE_DIFFICULTY };
}
export function consumeLoginChallenge(binding: string, proof: unknown, now = Date.now()): boolean {
  if (typeof proof !== 'string' || proof.length > 1024) return false;
  const [payload, signature, nonce, extra] = proof.split('.');
  if (
    extra !== undefined ||
    !payload ||
    !/^[A-Za-z0-9_-]{43}$/.test(signature ?? '') ||
    !/^\d{1,10}$/.test(nonce ?? '')
  )
    return false;
  const token = `${payload}.${signature}`;
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(mac(payload)))) return false;
  try {
    const value = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (
      value.binding !== binding ||
      !Number.isSafeInteger(value.expires) ||
      value.expires <= now ||
      value.expires > now + lifetime
    )
      return false;
    const hash = createHash('sha256').update(`${token}:${nonce}`).digest();
    if (hash[0] !== 0 || hash[1] !== 0 || hash[2] >= 4) return false;
    for (const [id, expires] of used) if (expires <= now) used.delete(id);
    if (used.has(token) || used.size >= 20_000) return false;
    used.set(token, value.expires);
    return true;
  } catch {
    return false;
  }
}
