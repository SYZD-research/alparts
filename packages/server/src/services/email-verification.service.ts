import { createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import { eq, lte, sql } from 'drizzle-orm';
import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { emailVerifications, users } from '../db/schema.js';
import { auditGuardedTransaction } from '../middleware/audit.js';
import { logError } from '../security/logger.js';
import { passwordPepper } from '../security/password-pepper.js';
import { emailDelivery, sendEmail } from './email.service.js';
import { existingAccountEmail, registrationCodeEmail, type EmailLocale } from './email-messages.js';

export const EMAIL_CODE_TTL_MS = 15 * 60_000;
export const MAX_EMAIL_CODE_ATTEMPTS = 5;
const MAX_PENDING_EMAIL_VERIFICATIONS = 10_000;

export function emailVerificationRequired(): boolean {
  return config.email.verification === 'required';
}

function codeDigest(normalizedEmail: string, code: string): string {
  return createHmac('sha256', passwordPepper())
    .update('alparts.email-verification.v1\0')
    .update(normalizedEmail)
    .update('\0')
    .update(code)
    .digest('hex');
}

function sameDigest(left: string, right: string): boolean {
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

async function deliver(to: string, { subject, text }: { subject: string; text: string }): Promise<void> {
  try {
    await sendEmail({ to, subject, text });
  } catch (error) {
    logError('email.delivery_failed', error);
    throw new Error('EMAIL_UNAVAILABLE');
  }
}

/**
 * Mails a registration code. An address that already has an account gets a
 * notice instead of a code, so the answer does not reveal which one it was.
 */
export async function sendRegistrationCode(normalizedEmail: string, locale: EmailLocale): Promise<void> {
  if (emailDelivery() === 'unavailable') throw new Error('REGISTRATION_UNAVAILABLE');
  const existing = await db.query.users.findFirst({ columns: { id: true }, where: eq(users.email, normalizedEmail) });
  if (existing) {
    await deliver(normalizedEmail, existingAccountEmail(locale));
    return;
  }
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  const codeHash = codeDigest(normalizedEmail, code);
  const expiresAt = new Date(Date.now() + EMAIL_CODE_TTL_MS);
  await auditGuardedTransaction(async (transaction) => {
    await transaction.delete(emailVerifications).where(lte(emailVerifications.expiresAt, new Date()));
    const [pending] = await transaction.select({ count: sql<number>`count(*)::int` }).from(emailVerifications);
    const [current] = await transaction.select({ email: emailVerifications.email })
      .from(emailVerifications)
      .where(eq(emailVerifications.email, normalizedEmail));
    if (!current && (pending?.count ?? 0) >= MAX_PENDING_EMAIL_VERIFICATIONS) throw new Error('REGISTRATION_BUSY');
    await transaction.insert(emailVerifications)
      .values({ email: normalizedEmail, codeHash, attempts: 0, expiresAt })
      .onConflictDoUpdate({
        target: emailVerifications.email,
        set: { codeHash, attempts: 0, expiresAt, createdAt: new Date() },
      });
  });
  await deliver(normalizedEmail, registrationCodeEmail(locale, code));
}

/** Spends the code for this address. A wrong code counts against it. */
export async function consumeRegistrationCode(normalizedEmail: string, code: string | undefined): Promise<void> {
  if (!emailVerificationRequired()) return;
  if (emailDelivery() === 'unavailable') throw new Error('REGISTRATION_UNAVAILABLE');
  if (!code || !/^\d{6}$/.test(code)) throw new Error('INVALID_EMAIL_CODE');
  const accepted = await auditGuardedTransaction(async (transaction) => {
    const [row] = await transaction.select()
      .from(emailVerifications)
      .where(eq(emailVerifications.email, normalizedEmail))
      .for('update');
    if (!row || row.expiresAt <= new Date() || row.attempts >= MAX_EMAIL_CODE_ATTEMPTS) return false;
    if (!sameDigest(row.codeHash, codeDigest(normalizedEmail, code))) {
      await transaction.update(emailVerifications)
        .set({ attempts: row.attempts + 1 })
        .where(eq(emailVerifications.email, normalizedEmail));
      return false;
    }
    await transaction.delete(emailVerifications).where(eq(emailVerifications.email, normalizedEmail));
    return true;
  });
  if (!accepted) throw new Error('INVALID_EMAIL_CODE');
}
