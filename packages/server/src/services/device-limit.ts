/**
 * The devices that make room for one more registration under the account's
 * device limit. `active` lists the account's devices that are not revoked,
 * oldest first. A device nobody approved holds its place without anyone's
 * decision, so the oldest of those make room; an approved device never does.
 * Null when the limit leaves no room.
 */
export function pendingDevicesToRetire(
  active: ReadonlyArray<{ id: string; approvedAt: Date | null }>,
  limit: number,
): string[] | null {
  const surplus = active.length + 1 - limit;
  if (surplus <= 0) return [];
  const pending = active.filter((device) => device.approvedAt === null);
  return pending.length >= surplus ? pending.slice(0, surplus).map((device) => device.id) : null;
}
