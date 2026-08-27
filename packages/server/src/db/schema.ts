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
  index,
  uniqueIndex,
  foreignKey,
  check,
} from 'drizzle-orm/pg-core';
import type { PgTableExtraConfig } from 'drizzle-orm/pg-core';
import { relations, sql } from 'drizzle-orm';

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

// === Devices & Crypto Keys ===

export const devices = pgTable('devices', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id),
  name: text('name').notNull(),
  identityKey: text('identity_key').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastActiveAt: timestamp('last_active_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
}, (t) => [
  unique('devices_id_user_id_unique').on(t.id, t.userId),
  index('devices_user_id_idx').on(t.userId),
]);

export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id),
  deviceId: uuid('device_id').references(() => devices.id),
  tokenHash: text('token_hash').unique().notNull(),
  deviceInfo: jsonb('device_info'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('sessions_user_id_idx').on(t.userId),
  index('sessions_device_id_idx').on(t.deviceId),
  index('sessions_expires_at_idx').on(t.expiresAt),
]);

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
}, (t) => [
  unique('roles_workspace_name_unique').on(t.workspaceId, t.name),
  unique('roles_workspace_id_unique').on(t.workspaceId, t.id),
  index('roles_workspace_id_idx').on(t.workspaceId),
]);

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
  userIdIdx: index('workspace_members_user_id_idx').on(t.userId),
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
  roleIdIdx: index('member_roles_role_id_idx').on(t.roleId),
}));

export const memberRolesRelations = relations(memberRoles, ({ one }) => ({
  member: one(workspaceMembers, { fields: [memberRoles.memberId], references: [workspaceMembers.id] }),
  role: one(roles, { fields: [memberRoles.roleId], references: [roles.id] }),
}));

export const workspaceInvitations = pgTable('workspace_invitations', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  roleId: uuid('role_id').references(() => roles.id, { onDelete: 'set null' }),
  tokenHash: text('token_hash').unique().notNull(),
  email: text('email'),
  createdBy: uuid('created_by').notNull().references(() => users.id),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  usedBy: uuid('used_by').references(() => users.id),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  revokedBy: uuid('revoked_by').references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('workspace_invitations_workspace_created_idx').on(t.workspaceId, t.createdAt),
  index('workspace_invitations_expires_at_idx').on(t.expiresAt),
  index('workspace_invitations_role_id_idx').on(t.roleId),
]);

// === Categories & Channels ===

export const categories = pgTable('categories', {
  id: uuid('id').primaryKey().defaultRandom(),
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  unique('categories_workspace_id_unique').on(t.workspaceId, t.id),
  index('categories_workspace_position_idx').on(t.workspaceId, t.position),
]);

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
  keyRotationRequired: boolean('key_rotation_required').default(false).notNull(),
  topic: text('topic'),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  unique('channels_workspace_id_unique').on(t.workspaceId, t.id),
  index('channels_workspace_position_idx').on(t.workspaceId, t.position),
  index('channels_category_position_idx').on(t.categoryId, t.position),
]);

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
  userIdIdx: index('channel_members_user_id_idx').on(t.userId),
}));

export const categoryRolePermissionOverrides = pgTable('category_role_permission_overrides', {
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id, { onDelete: 'cascade' }),
  categoryId: uuid('category_id').notNull(),
  roleId: uuid('role_id').notNull(),
  allowMask: integer('allow_mask').notNull().default(0),
  denyMask: integer('deny_mask').notNull().default(0),
  revision: integer('revision').notNull().default(1),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.workspaceId, t.categoryId, t.roleId] }),
  categoryWorkspaceFk: foreignKey({
    name: 'category_role_overrides_category_workspace_fk',
    columns: [t.workspaceId, t.categoryId],
    foreignColumns: [categories.workspaceId, categories.id],
  }).onDelete('cascade'),
  roleWorkspaceFk: foreignKey({
    name: 'category_role_overrides_role_workspace_fk',
    columns: [t.workspaceId, t.roleId],
    foreignColumns: [roles.workspaceId, roles.id],
  }),
  roleIdx: index('category_role_permission_overrides_role_idx').on(t.workspaceId, t.roleId),
  targetIdx: index('category_role_permission_overrides_category_idx').on(t.categoryId),
  allowMaskCheck: check('category_role_permission_overrides_allow_mask_check', sql`${t.allowMask} >= 0 and (${t.allowMask} & ${sql.raw('-16512')}) = 0`),
  denyMaskCheck: check('category_role_permission_overrides_deny_mask_check', sql`${t.denyMask} >= 0 and (${t.denyMask} & ${sql.raw('-16512')}) = 0`),
  revisionCheck: check('category_role_permission_overrides_revision_check', sql`${t.revision} >= 1`),
}));

export const channelRolePermissionOverrides = pgTable('channel_role_permission_overrides', {
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id, { onDelete: 'cascade' }),
  channelId: uuid('channel_id').notNull(),
  roleId: uuid('role_id').notNull(),
  allowMask: integer('allow_mask').notNull().default(0),
  denyMask: integer('deny_mask').notNull().default(0),
  revision: integer('revision').notNull().default(1),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.workspaceId, t.channelId, t.roleId] }),
  channelWorkspaceFk: foreignKey({
    name: 'channel_role_overrides_channel_workspace_fk',
    columns: [t.workspaceId, t.channelId],
    foreignColumns: [channels.workspaceId, channels.id],
  }).onDelete('cascade'),
  roleWorkspaceFk: foreignKey({
    name: 'channel_role_overrides_role_workspace_fk',
    columns: [t.workspaceId, t.roleId],
    foreignColumns: [roles.workspaceId, roles.id],
  }),
  roleIdx: index('channel_role_permission_overrides_role_idx').on(t.workspaceId, t.roleId),
  targetIdx: index('channel_role_permission_overrides_channel_idx').on(t.channelId),
  allowMaskCheck: check('channel_role_permission_overrides_allow_mask_check', sql`${t.allowMask} >= 0 and (${t.allowMask} & ${sql.raw('-16512')}) = 0`),
  denyMaskCheck: check('channel_role_permission_overrides_deny_mask_check', sql`${t.denyMask} >= 0 and (${t.denyMask} & ${sql.raw('-16512')}) = 0`),
  revisionCheck: check('channel_role_permission_overrides_revision_check', sql`${t.revision} >= 1`),
}));

export const channelKeys = pgTable('channel_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull().default(1),
  encryptedKey: text('encrypted_key').notNull(),
  deviceId: uuid('device_id').notNull().references(() => devices.id),
  distributorDeviceId: uuid('distributor_device_id').references(() => devices.id),
  signature: text('signature'),
  confirmedAt: timestamp('confirmed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t): PgTableExtraConfig => ({
  uniqueRecipientDistributor: unique('channel_keys_recipient_distributor_unique')
    .on(t.channelId, t.version, t.deviceId, t.distributorDeviceId)
    .nullsNotDistinct(),
  uniqueRecipientDelivery: unique('channel_keys_recipient_delivery_unique')
    .on(t.channelId, t.version, t.deviceId, t.id),
  epochRecipientFk: foreignKey({
    name: 'channel_keys_epoch_recipient_fk',
    columns: [t.channelId, t.version, t.deviceId],
    foreignColumns: [
      channelKeyEpochRecipients.channelId,
      channelKeyEpochRecipients.version,
      channelKeyEpochRecipients.deviceId,
    ],
  }),
  channelVersionIdx: index('channel_keys_channel_version_idx').on(t.channelId, t.version),
  deviceIdIdx: index('channel_keys_device_id_idx').on(t.deviceId),
  distributorDeviceIdIdx: index('channel_keys_distributor_device_id_idx').on(t.distributorDeviceId),
  signaturePairCheck: check(
    'channel_keys_signature_pair_check',
    sql`(${t.distributorDeviceId} is null and ${t.signature} is null) or (${t.distributorDeviceId} is not null and ${t.signature} is not null)`,
  ),
}));

export const channelKeyEpochs = pgTable('channel_key_epochs', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull(),
  protocolVersion: integer('protocol_version').notNull().default(2),
  status: text('status').notNull().default('pending'),
  keyCommitment: text('key_commitment').notNull(),
  distributorDeviceId: uuid('distributor_device_id').notNull().references(() => devices.id),
  activatedAt: timestamp('activated_at', { withTimezone: true }),
  abortedAt: timestamp('aborted_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.channelId, t.version] }),
  onePendingPerChannel: uniqueIndex('channel_key_epochs_one_pending_per_channel_idx')
    .on(t.channelId)
    .where(sql`${t.status} = 'pending'`),
  oneActivePerChannel: uniqueIndex('channel_key_epochs_one_active_per_channel_idx')
    .on(t.channelId)
    .where(sql`${t.status} = 'active'`),
  distributorDeviceIdIdx: index('channel_key_epochs_distributor_device_id_idx').on(t.distributorDeviceId),
  versionCheck: check('channel_key_epochs_version_check', sql`${t.version} >= 1`),
  protocolVersionCheck: check('channel_key_epochs_protocol_version_check', sql`${t.protocolVersion} >= 1`),
  statusCheck: check(
    'channel_key_epochs_status_check',
    sql`${t.status} in ('pending', 'active', 'retired', 'aborted')`,
  ),
  statusTimestampsCheck: check(
    'channel_key_epochs_status_timestamps_check',
    sql`(${t.status} = 'pending' and ${t.activatedAt} is null and ${t.abortedAt} is null)
      or (${t.status} = 'active' and ${t.activatedAt} is not null and ${t.abortedAt} is null)
      or (${t.status} = 'retired' and ${t.abortedAt} is null)
      or (${t.status} = 'aborted' and ${t.activatedAt} is null and ${t.abortedAt} is not null)`,
  ),
  commitmentCheck: check('channel_key_epochs_commitment_check', sql`${t.keyCommitment} ~ '^[A-Za-z0-9_-]{43}$'`),
}));

export const channelKeyEpochRecipients = pgTable('channel_key_epoch_recipients', {
  channelId: uuid('channel_id').notNull(),
  version: integer('version').notNull(),
  deviceId: uuid('device_id').notNull().references(() => devices.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  requiredForActivation: boolean('required_for_activation').notNull().default(true),
  acceptedDeliveryId: uuid('accepted_delivery_id'),
  acknowledgementSignature: text('acknowledgement_signature'),
  acknowledgedAt: timestamp('acknowledged_at', { withTimezone: true }),
}, (t): PgTableExtraConfig => ({
  pk: primaryKey({ columns: [t.channelId, t.version, t.deviceId] }),
  epochFk: foreignKey({
    name: 'channel_key_epoch_recipients_epoch_fk',
    columns: [t.channelId, t.version],
    foreignColumns: [channelKeyEpochs.channelId, channelKeyEpochs.version],
  }),
  deviceUserFk: foreignKey({
    name: 'channel_key_epoch_recipients_device_user_fk',
    columns: [t.deviceId, t.userId],
    foreignColumns: [devices.id, devices.userId],
  }),
  acceptedDeliveryFk: foreignKey({
    name: 'channel_key_epoch_recipients_accepted_delivery_fk',
    columns: [t.channelId, t.version, t.deviceId, t.acceptedDeliveryId],
    foreignColumns: [channelKeys.channelId, channelKeys.version, channelKeys.deviceId, channelKeys.id],
  }),
  epochIdx: index('channel_key_epoch_recipients_epoch_idx').on(t.channelId, t.version),
  deviceIdIdx: index('channel_key_epoch_recipients_device_id_idx').on(t.deviceId),
  userIdIdx: index('channel_key_epoch_recipients_user_id_idx').on(t.userId),
  acceptedDeliveryIdIdx: index('channel_key_epoch_recipients_accepted_delivery_id_idx').on(t.acceptedDeliveryId),
  acknowledgementCheck: check(
    'channel_key_epoch_recipients_acknowledgement_check',
    sql`(${t.acceptedDeliveryId} is null and ${t.acknowledgementSignature} is null and ${t.acknowledgedAt} is null)
      or (${t.acceptedDeliveryId} is not null and ${t.acknowledgementSignature} is not null and ${t.acknowledgedAt} is not null)`,
  ),
}));

// === Messages ===

export const messages = pgTable('messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  authorId: uuid('author_id').notNull().references(() => users.id),
  deviceId: uuid('device_id').references(() => devices.id),
  content: text('content').notNull(),
  contentNonce: text('content_nonce').notNull(),
  keyVersion: integer('key_version').notNull().default(1),
  signature: text('signature'),
  // Null marks legacy v2 envelopes. New v3 envelopes always carry an
  // authenticated boolean, including false, so clients can distinguish a
  // literal broadcast word from an authorized broadcast mention.
  broadcastMention: boolean('broadcast_mention'),
  type: text('type').notNull().default('message'),
  reactionAction: text('reaction_action'),
  refMessageId: uuid('ref_message_id'),
  idempotencyKey: text('idempotency_key'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  uniqueChannelIdempotency: unique().on(t.channelId, t.idempotencyKey),
  channelCreatedIdx: index('messages_channel_created_idx').on(t.channelId, t.createdAt, t.id),
  referenceTypeIdx: index('messages_reference_type_idx').on(t.refMessageId, t.type),
  authorIdIdx: index('messages_author_id_idx').on(t.authorId),
  reactionActionCheck: check('messages_reaction_action_check', sql`${t.reactionAction} is null or ${t.reactionAction} in ('add', 'remove')`),
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
  messageIdIdx: index('message_pins_message_id_idx').on(t.messageId),
}));

export const messageReactions = pgTable('message_reactions', {
  messageId: uuid('message_id').notNull().references(() => messages.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  emoji: text('emoji').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.messageId, t.userId, t.emoji] }),
  messageIdIdx: index('message_reactions_message_id_idx').on(t.messageId),
}));

export const readPositions = pgTable('read_positions', {
  userId: uuid('user_id').notNull().references(() => users.id),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  lastReadMessageId: uuid('last_read_message_id'),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.userId, t.channelId] }),
  channelIdIdx: index('read_positions_channel_id_idx').on(t.channelId),
}));

export const channelPreferences = pgTable('channel_preferences', {
  userId: uuid('user_id').notNull().references(() => users.id),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  favorite: boolean('favorite').default(false).notNull(),
  muted: boolean('muted').default(false).notNull(),
  hidden: boolean('hidden').default(false).notNull(),
  notificationLevel: text('notification_level').default('all').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.userId, t.channelId] }),
  channelIdIdx: index('channel_preferences_channel_id_idx').on(t.channelId),
}));

export const messageBookmarks = pgTable('message_bookmarks', {
  userId: uuid('user_id').notNull().references(() => users.id),
  messageId: uuid('message_id').notNull().references(() => messages.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.userId, t.messageId] }),
  messageIdIdx: index('message_bookmarks_message_id_idx').on(t.messageId),
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
  userIdIdx: index('dm_members_user_id_idx').on(t.userId),
}));

// === Attachments ===

export const attachments = pgTable('attachments', {
  id: uuid('id').primaryKey().defaultRandom(),
  messageId: uuid('message_id').notNull().references(() => messages.id),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  signerDeviceId: uuid('signer_device_id').references(() => devices.id),
  keyVersion: integer('key_version').notNull(),
  signature: text('signature'),
  filenameEnc: text('filename_enc').notNull(),
  mimeType: text('mime_type').notNull(),
  sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
  storageKey: text('storage_key').unique().notNull(),
  chunkCount: integer('chunk_count').notNull().default(1),
  wrappedKey: text('wrapped_key').notNull(),
  contentNonce: text('content_nonce').notNull(),
  cryptoManifest: jsonb('crypto_manifest').notNull().default({ version: 0 }),
  thumbnailKey: text('thumbnail_key'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('attachments_message_id_idx').on(t.messageId),
  index('attachments_channel_id_idx').on(t.channelId),
  index('attachments_signer_device_id_idx').on(t.signerDeviceId),
  check('attachments_key_version_check', sql`${t.keyVersion} >= 1`),
  check(
    'attachments_signature_pair_check',
    sql`(${t.signerDeviceId} is null and ${t.signature} is null) or (${t.signerDeviceId} is not null and ${t.signature} is not null)`,
  ),
]);

export const attachmentUploads = pgTable('attachment_uploads', {
  id: uuid('id').primaryKey().defaultRandom(),
  messageId: uuid('message_id').notNull().references(() => messages.id),
  uploaderId: uuid('uploader_id').notNull().references(() => users.id),
  storageKey: text('storage_key').unique().notNull(),
  filenameEnc: text('filename_enc').notNull(),
  mimeType: text('mime_type').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  completedAt: timestamp('completed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('attachment_uploads_message_id_idx').on(t.messageId),
  index('attachment_uploads_uploader_id_idx').on(t.uploaderId),
  index('attachment_uploads_expires_at_idx').on(t.expiresAt),
]);

export const attachmentUploadChunks = pgTable('attachment_upload_chunks', {
  uploadId: uuid('upload_id').notNull().references(() => attachmentUploads.id, { onDelete: 'cascade' }),
  chunkIndex: integer('chunk_index').notNull(),
  sizeBytes: integer('size_bytes').notNull(),
  storageKey: text('storage_key').unique().notNull(),
  etag: text('etag').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.uploadId, t.chunkIndex] }),
}));

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
}, (t) => [
  index('audit_logs_created_at_idx').on(t.createdAt, t.id),
  index('audit_logs_target_created_idx').on(t.targetType, t.targetId, t.createdAt.desc(), t.id.desc()),
  index('audit_logs_workspace_details_created_idx').on(
    sql`(${t.details}->>'workspaceId')`,
    t.createdAt.desc(),
    t.id.desc(),
  ),
]);
