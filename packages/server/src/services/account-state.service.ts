import { and, asc, eq, isNull, sql } from 'drizzle-orm';
import { devices, passkeys, sessions, users } from '../db/schema.js';
import { auditedTransaction } from '../middleware/audit.js';
import { MAX_ACTIVE_DEVICES_PER_USER } from '../security/limits.js';
import { expireUnapprovedDevice } from './device.service.js';
import { lockKeyProtocol } from './key.service.js';

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
 * Approved devices stay: revoking one needs an entry signed by another device
 * of the user, which the server cannot make; the user revokes the ones they do
 * not recognize after signing in. Devices nobody approved are retired, since
 * a full set of them would keep the owner from adding a device or restoring
 * one with the recovery code.
 */
export async function resetPassword(
  userId: string,
  passwordHash: string,
): Promise<{ passkeysRemoved: number; devicesRetired: string[] }> {
  return auditedTransaction(async (tx) => {
    // Retiring a device appends to the user's directory, which is done under
    // this lock.
    await lockKeyProtocol(tx);
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`passkeys:${userId}`})::bigint)`);
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`sessions:${userId}`})::bigint)`);
    const [user] = await tx.select({ id: users.id }).from(users).where(eq(users.id, userId)).for('update');
    if (!user) throw new Error('USER_NOT_FOUND');
    await tx.update(users)
      .set({ passwordHash, passwordLoginDisabled: false, updatedAt: new Date() })
      .where(eq(users.id, userId));
    const pending = await tx.select({ id: devices.id })
      .from(devices)
      .where(and(eq(devices.userId, userId), isNull(devices.approvedAt), isNull(devices.revokedAt)))
      .orderBy(asc(devices.createdAt), asc(devices.id))
      .limit(MAX_ACTIVE_DEVICES_PER_USER + 1) as Array<{ id: string }>;
    if (pending.length > MAX_ACTIVE_DEVICES_PER_USER) throw new Error('DEVICE_INVARIANT_EXCEEDED');
    for (const device of pending) await expireUnapprovedDevice(tx, userId, device.id);
    const removed = await tx.delete(passkeys).where(eq(passkeys.userId, userId)).returning({ id: passkeys.id });
    await tx.delete(sessions).where(eq(sessions.userId, userId));
    // Closes the account's open connections, as for a disabled account.
    await tx.execute(sql`select pg_notify('alparts_account_disabled', ${userId})`);
    return { passkeysRemoved: removed.length, devicesRetired: pending.map((device) => device.id) };
  }, (result) => [
    {
      action: 'account.password.reset',
      targetType: 'user',
      targetId: userId,
      details: { passkeysRemoved: result.passkeysRemoved, devicesRetired: result.devicesRetired.length },
    },
    ...result.devicesRetired.map((deviceId) => ({
      action: 'device.expire',
      targetType: 'device',
      targetId: deviceId,
      details: { reason: 'password-reset' },
    })),
  ]);
}
