import { db } from '../db/index.js';
import { channels, channelMembers, categories, workspaceMembers } from '../db/schema.js';
import { eq, and, asc } from 'drizzle-orm';
import { audit } from '../middleware/audit.js';

export async function getWorkspaceChannels(workspaceId: string, userId: string) {
  const allChannels = await db.query.channels.findMany({
    where: eq(channels.workspaceId, workspaceId),
    orderBy: [asc(channels.position)],
  });

  const result = [];
  for (const ch of allChannels) {
    if (!ch.isPrivate) {
      result.push(formatChannel(ch));
      continue;
    }
    const membership = await db.query.channelMembers.findFirst({
      where: and(
        eq(channelMembers.channelId, ch.id),
        eq(channelMembers.userId, userId),
      ),
    });
    if (membership) {
      result.push(formatChannel(ch));
    }
  }

  return result;
}

export async function getWorkspaceCategories(workspaceId: string) {
  const cats = await db.query.categories.findMany({
    where: eq(categories.workspaceId, workspaceId),
    orderBy: [asc(categories.position)],
    with: {
      channels: {
        orderBy: [asc(channels.position)],
      },
    },
  });

  return cats.map((c: any) => ({
    id: c.id,
    workspaceId: c.workspaceId,
    name: c.name,
    position: c.position,
    channels: c.channels.map((ch: any) => formatChannel(ch)),
  }));
}

export async function createChannel(
  workspaceId: string,
  name: string,
  type: string = 'text',
  options?: { categoryId?: string; isPrivate?: boolean; topic?: string; position?: number },
) {
  const [channel] = await db.insert(channels).values({
    workspaceId,
    name,
    type,
    categoryId: options?.categoryId || null,
    isPrivate: options?.isPrivate || false,
    topic: options?.topic || null,
    position: options?.position || 0,
  }).returning();

  await audit({
    action: 'channel.create',
    targetType: 'channel',
    targetId: channel.id,
    details: { workspaceId, name, type },
  });

  return formatChannel(channel);
}

export async function getChannelById(channelId: string) {
  const channel = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!channel) return null;
  return formatChannel(channel);
}

export async function updateChannel(channelId: string, updates: { name?: string; topic?: string; categoryId?: string; position?: number; isPrivate?: boolean }) {
  const [channel] = await db.update(channels)
    .set({ ...updates })
    .where(eq(channels.id, channelId))
    .returning();
  if (!channel) return null;
  return formatChannel(channel);
}

export async function deleteChannel(channelId: string) {
  await db.delete(channels).where(eq(channels.id, channelId));
}

export async function createCategory(workspaceId: string, name: string, position?: number) {
  const [category] = await db.insert(categories).values({
    workspaceId,
    name,
    position: position || 0,
  }).returning();

  await audit({
    action: 'category.create',
    targetType: 'category',
    targetId: category.id,
    details: { workspaceId, name },
  });

  return category;
}

export async function isChannelMember(channelId: string, userId: string): Promise<boolean> {
  const channel = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!channel) return false;

  if (!channel.isPrivate) return true;

  const membership = await db.query.channelMembers.findFirst({
    where: and(
      eq(channelMembers.channelId, channelId),
      eq(channelMembers.userId, userId),
    ),
  });
  return !!membership;
}

export async function getChannelMembers(channelId: string) {
  const ch = await db.query.channels.findFirst({
    where: eq(channels.id, channelId),
  });
  if (!ch) return [];

  if (!ch.isPrivate) {
    const wsMembers = await db.query.workspaceMembers.findMany({
      where: eq(workspaceMembers.workspaceId, ch.workspaceId),
      with: { user: true },
    });
    return wsMembers.map((m: any) => ({
      id: m.user.id,
      displayName: m.user.displayName,
      avatarUrl: m.user.avatarUrl,
      status: m.user.status,
    }));
  }

  const members = await db.query.channelMembers.findMany({
    where: eq(channelMembers.channelId, channelId),
  });

  const result = [];
  for (const m of members) {
    const user = await db.query.users.findFirst({ where: eq(workspaceMembers.userId, m.userId) });
    if (user) {
      result.push({
        id: user.id,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
        status: user.status,
      });
    }
  }
  return result;
}

function formatChannel(ch: any) {
  return {
    id: ch.id,
    workspaceId: ch.workspaceId,
    categoryId: ch.categoryId,
    name: ch.name,
    type: ch.type,
    isPrivate: ch.isPrivate,
    topic: ch.topic,
    position: ch.position,
    createdAt: ch.createdAt.toISOString(),
  };
}
