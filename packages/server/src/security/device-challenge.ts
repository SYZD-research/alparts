import { randomBytes, timingSafeEqual } from 'node:crypto';

const CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const MAX_CHALLENGES = 20_000;

interface ChallengeEntry {
  value: string;
  userId: string;
  expiresAt: number;
}

export class DeviceChallengeStore {
  private readonly challenges = new Map<string, ChallengeEntry>();

  issue(userId: string, sessionId: string, now = Date.now()): string {
    this.prune(now);
    if (!this.challenges.has(sessionId) && this.challenges.size >= MAX_CHALLENGES) {
      throw new Error('DEVICE_CHALLENGE_CAPACITY');
    }
    const value = randomBytes(32).toString('base64url');
    this.challenges.set(sessionId, { value, userId, expiresAt: now + CHALLENGE_LIFETIME_MS });
    return value;
  }

  consume(userId: string, sessionId: string, supplied: string, now = Date.now()): boolean {
    const entry = this.challenges.get(sessionId);
    this.challenges.delete(sessionId);
    if (!entry || entry.userId !== userId || entry.expiresAt <= now) return false;
    const expected = Buffer.from(entry.value, 'utf8');
    const actual = Buffer.from(supplied, 'utf8');
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  private prune(now: number): void {
    for (const [sessionId, entry] of this.challenges) {
      if (entry.expiresAt <= now) this.challenges.delete(sessionId);
    }
  }
}

export const deviceChallenges = new DeviceChallengeStore();
