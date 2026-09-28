import { eq, sql } from 'drizzle-orm';
import { sessions, users } from '../db/schema.js';
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
