import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../db/index.js';
import { users, sessions } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';
import { config } from '../config/index.js';
import { v4 as uuidv4 } from 'uuid';
import { audit } from '../middleware/audit.js';

const SALT_ROUNDS = 12;

export async function register(email: string, password: string, displayName: string) {
  const existing = await db.query.users.findFirst({
    where: eq(users.email, email),
  });
  if (existing) {
    throw new Error('EMAIL_EXISTS');
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const [user] = await db.insert(users).values({
    email,
    passwordHash,
    displayName,
  }).returning();

  await audit({
    actorId: user.id,
    action: 'user.register',
    targetType: 'user',
    targetId: user.id,
  });

  return { id: user.id, email: user.email, displayName: user.displayName };
}

export async function login(email: string, password: string, deviceInfo?: Record<string, unknown>) {
  const user = await db.query.users.findFirst({
    where: eq(users.email, email),
  });
  if (!user) {
    throw new Error('INVALID_CREDENTIALS');
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    throw new Error('INVALID_CREDENTIALS');
  }

  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  const token = jwt.sign(
    { userId: user.id, sessionId },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn as string } as jwt.SignOptions,
  );

  await db.insert(sessions).values({
    id: sessionId,
    userId: user.id,
    token,
    deviceInfo: deviceInfo || null,
    expiresAt,
  });

  await db.update(users)
    .set({ updatedAt: new Date() })
    .where(eq(users.id, user.id));

  await audit({
    actorId: user.id,
    action: 'user.login',
    targetType: 'user',
    targetId: user.id,
  });

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      status: user.status,
      createdAt: user.createdAt.toISOString(),
    },
  };
}

export async function logout(sessionId: string) {
  await db.delete(sessions).where(eq(sessions.id, sessionId));
}

export async function getUserById(userId: string) {
  const user = await db.query.users.findFirst({
    where: eq(users.id, userId),
  });
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    createdAt: user.createdAt.toISOString(),
  };
}
