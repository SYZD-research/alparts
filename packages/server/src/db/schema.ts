import {
  pgTable,
  uuid,
  text,
  timestamp,
  bigint,
  integer,
  boolean,
  jsonb,
  unique,
  primaryKey,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// === Users & Auth ===

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').unique().notNull(),
  passwordHash: text('password_hash').notNull(),
  displayName: text('display_name').notNull(),
  avatarUrl: text('avatar_url'),
  status: text('status').default('offline').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const usersRelations = relations(users, ({ many }) => ({
  workspaceMembers: many(workspaceMembers),
  devices: many(devices),
}));

export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id),
  token: text('token').unique().notNull(),
  deviceInfo: jsonb('device_info'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// === Devices & Crypto Keys ===

export const devices = pgTable('devices', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id),
  name: text('name').notNull(),
  identityKey: text('identity_key').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastActiveAt: timestamp('last_active_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});

export const devicesRelations = relations(devices, ({ one }) => ({
  user: one(users, { fields: [devices.userId], references: [users.id] }),
}));

// === Workspaces ===

export const workspaces = pgTable('workspaces', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  iconUrl: text('icon_url'),
  ownerId: uuid('owner_id').notNull().references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const workspacesRelations = relations(workspaces, ({ many }) => ({
  members: many(workspaceMembers),
  roles: many(roles),
  categories: many(categories),
  channels: many(channels),
}));

export const roles = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  permissions: integer('permissions').notNull().default(0),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const rolesRelations = relations(roles, ({ one, many }) => ({
  workspace: one(workspaces, { fields: [roles.workspaceId], references: [workspaces.id] }),
  memberRoles: many(memberRoles),
}));

export const workspaceMembers = pgTable('workspace_members', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  joinedAt: timestamp('joined_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  uniqueWorkspaceUser: unique().on(t.workspaceId, t.userId),
}));

export const workspaceMembersRelations = relations(workspaceMembers, ({ one, many }) => ({
  workspace: one(workspaces, { fields: [workspaceMembers.workspaceId], references: [workspaces.id] }),
  user: one(users, { fields: [workspaceMembers.userId], references: [users.id] }),
  memberRoles: many(memberRoles),
}));

export const memberRoles = pgTable('member_roles', {
  memberId: uuid('member_id').notNull().references(() => workspaceMembers.id),
  roleId: uuid('role_id').notNull().references(() => roles.id),
}, (t) => ({
  pk: primaryKey({ columns: [t.memberId, t.roleId] }),
}));

export const memberRolesRelations = relations(memberRoles, ({ one }) => ({
  member: one(workspaceMembers, { fields: [memberRoles.memberId], references: [workspaceMembers.id] }),
  role: one(roles, { fields: [memberRoles.roleId], references: [roles.id] }),
}));

// === Categories & Channels ===

export const categories = pgTable('categories', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const categoriesRelations = relations(categories, ({ one, many }) => ({
  workspace: one(workspaces, { fields: [categories.workspaceId], references: [workspaces.id] }),
  channels: many(channels),
}));

export const channels = pgTable('channels', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  categoryId: uuid('category_id').references(() => categories.id),
  name: text('name').notNull(),
  type: text('type').notNull().default('text'),
  isPrivate: boolean('is_private').default(false).notNull(),
  topic: text('topic'),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const channelsRelations = relations(channels, ({ one }) => ({
  workspace: one(workspaces, { fields: [channels.workspaceId], references: [workspaces.id] }),
  category: one(categories, { fields: [channels.categoryId], references: [categories.id] }),
}));

export const channelMembers = pgTable('channel_members', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  joinedAt: timestamp('joined_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.channelId, t.userId] }),
}));

export const channelKeys = pgTable('channel_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull().default(1),
  encryptedKey: text('encrypted_key').notNull(),
  deviceId: uuid('device_id').notNull().references(() => devices.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// === Messages ===

export const messages = pgTable('messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  authorId: uuid('author_id').notNull().references(() => users.id),
  deviceId: uuid('device_id'),
  content: text('content').notNull(),
  contentNonce: text('content_nonce').notNull(),
  type: text('type').notNull().default('message'),
  refMessageId: uuid('ref_message_id'),
  idempotencyKey: text('idempotency_key'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  uniqueChannelIdempotency: unique().on(t.channelId, t.idempotencyKey),
}));

export const messagesRelations = relations(messages, ({ one }) => ({
  author: one(users, { fields: [messages.authorId], references: [users.id] }),
  channel: one(channels, { fields: [messages.channelId], references: [channels.id] }),
}));

export const messagePins = pgTable('message_pins', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  messageId: uuid('message_id').notNull().references(() => messages.id),
  pinnedBy: uuid('pinned_by').notNull().references(() => users.id),
  pinnedAt: timestamp('pinned_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.channelId, t.messageId] }),
}));

export const readPositions = pgTable('read_positions', {
  userId: uuid('user_id').notNull().references(() => users.id),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  lastReadMessageId: uuid('last_read_message_id'),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.userId, t.channelId] }),
}));

// === DM ===

export const dmConversations = pgTable('dm_conversations', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').unique().notNull().references(() => channels.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const dmMembers = pgTable('dm_members', {
  conversationId: uuid('conversation_id').notNull().references(() => dmConversations.id),
  userId: uuid('user_id').notNull().references(() => users.id),
}, (t) => ({
  pk: primaryKey({ columns: [t.conversationId, t.userId] }),
}));

// === Attachments ===

export const attachments = pgTable('attachments', {
  id: uuid('id').primaryKey().defaultRandom(),
  messageId: uuid('message_id').notNull().references(() => messages.id),
  filenameEnc: text('filename_enc').notNull(),
  mimeType: text('mime_type').notNull(),
  sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
  storageKey: text('storage_key').notNull(),
  encryptionKey: text('encryption_key').notNull(),
  thumbnailKey: text('thumbnail_key'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// === Audit Log ===

export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  actorId: uuid('actor_id'),
  action: text('action').notNull(),
  targetType: text('target_type'),
  targetId: uuid('target_id'),
  details: jsonb('details'),
  prevHash: text('prev_hash'),
  hash: text('hash').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});
