import { db } from '../db/index.js';
import { devices } from '../db/schema.js';
import { eq, and, isNull } from 'drizzle-orm';
import { audit } from '../middleware/audit.js';

export async function registerDevice(userId: string, name: string, identityKey: string) {
  const [device] = await db.insert(devices).values({
    userId,
    name,
    identityKey,
  }).returning();

  await audit({
    actorId: userId,
    action: 'device.register',
    targetType: 'device',
    targetId: device.id,
    details: { name },
  });

  return {
    id: device.id,
    userId: device.userId,
    name: device.name,
    identityKey: device.identityKey,
    createdAt: device.createdAt.toISOString(),
    lastActiveAt: device.lastActiveAt?.toISOString() || null,
    revokedAt: device.revokedAt?.toISOString() || null,
  };
}

export async function getUserDevices(userId: string) {
  const userDevices = await db.query.devices.findMany({
    where: and(
      eq(devices.userId, userId),
      isNull(devices.revokedAt),
    ),
  });

  return userDevices.map(d => ({
    id: d.id,
    userId: d.userId,
    name: d.name,
    identityKey: d.identityKey,
    createdAt: d.createdAt.toISOString(),
    lastActiveAt: d.lastActiveAt?.toISOString() || null,
    revokedAt: null,
  }));
}

export async function revokeDevice(deviceId: string, userId: string) {
  const device = await db.query.devices.findFirst({
    where: eq(devices.id, deviceId),
  });
  if (!device) throw new Error('DEVICE_NOT_FOUND');
  if (device.userId !== userId) throw new Error('NOT_AUTHORIZED');

  await db.update(devices)
    .set({ revokedAt: new Date() })
    .where(eq(devices.id, deviceId));

  await audit({
    actorId: userId,
    action: 'device.revoke',
    targetType: 'device',
    targetId: deviceId,
  });
}

export async function getDeviceById(deviceId: string) {
  return db.query.devices.findFirst({
    where: eq(devices.id, deviceId),
  });
}

export async function updateLastActive(deviceId: string) {
  await db.update(devices)
    .set({ lastActiveAt: new Date() })
    .where(eq(devices.id, deviceId));
}
