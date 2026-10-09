import { eq, sql } from 'drizzle-orm';
import { passkeys, sessions, users } from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';

/** Operator-only incident response; intentionally not exposed to workspace admins. */
export async function setAccountDisabled(userId: string, disabled: boolean): Promise<void> {
  await auditedTransaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    const [user] = await tx.select().from(users).where(eq(users.id, userId)).for('update');
    if (!user) throw new Error('USER_NOT_FOUND');
    await tx.update(users).set({ disabledAt: disabled ? new Date() : null, updatedAt: new Date() }).where(eq(users.id, userId));
    if (disabled) {
      await tx.delete(sessions).where(eq(sessions.userId, userId));
      await tx.execute(sql`select pg_notify('alparts_account_disabled', ${userId})`);
    }
    return null;
  }, () => ({ action: disabled ? 'account.disable' : 'account.enable', targetType: 'user', targetId: userId }));
}

/**
 * Operator-only recovery for a user who cannot sign in: sets a new password,
 * turns password login back on, removes every passkey and ends every login of
 * the account. Someone who can sign in needs no reset, so after a takeover
 * the passkeys may include the attacker's: kept, they would sign the attacker
 * in again, and confirming an action would need a passkey the user may not
 * have (formal model M4s AS3-pk). The user registers a passkey again.
 * Devices stay: revoking one needs an entry signed by another device of the
 * user, which the server cannot make; the user revokes the ones they do not
 * recognize after signing in.
 */
export async function resetPassword(userId: string, passwordHash: string): Promise<{ passkeysRemoved: number }> {
  return auditedTransaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`);
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    const [user] = await tx.select({ id: users.id }).from(users).where(eq(users.id, userId)).for('update');
    if (!user) throw new Error('USER_NOT_FOUND');
    await tx.update(users)
      .set({ passwordHash, passwordLoginDisabled: false, updatedAt: new Date() })
      .where(eq(users.id, userId));
    const removed = await tx.delete(passkeys).where(eq(passkeys.userId, userId)).returning({ id: passkeys.id });
    await tx.delete(sessions).where(eq(sessions.userId, userId));
    // Closes the account's open connections, as for a disabled account.
    await tx.execute(sql`select pg_notify('alparts_account_disabled', ${userId})`);
    return { passkeysRemoved: removed.length };
  }, (result) => ({
    action: 'account.password.reset',
    targetType: 'user',
    targetId: userId,
    details: { passkeysRemoved: result.passkeysRemoved },
  }));
}
