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
  disabledAt: timestamp('disabled_at', { withTimezone: true }),
  // Set by the user once a passkey exists; an operator reset clears it.
  passwordLoginDisabled: boolean('password_login_disabled').default(false).notNull(),
  bio: text('bio'),
  avatarObjectKey: text('avatar_object_key'),
  profileUpdatedAt: timestamp('profile_updated_at', { withTimezone: true }),
  flagAppealUsedAt: timestamp('flag_appeal_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  check('users_bio_length_check', sql`${t.bio} IS NULL OR char_length(${t.bio}) <= 200`),
  check('users_avatar_key_check', sql`${t.avatarObjectKey} IS NULL OR ${t.avatarObjectKey} ~ '^avatars/v1/[0-9a-f-]{36}/[0-9a-f-]{36}$'`),
]);

export const profileFlags = pgTable('profile_flags', {
  workspaceId: uuid('workspace_id').notNull().references(() => workspaces.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  flaggedBy: uuid('flagged_by').notNull().references(() => users.id),
  flaggedAt: timestamp('flagged_at', { withTimezone: true }).defaultNow().notNull(),
  appealStatus: text('appeal_status').default('none').notNull(),
  appealRequestedAt: timestamp('appeal_requested_at', { withTimezone: true }),
}, (t) => [
  primaryKey({ name: 'profile_flags_pk', columns: [t.workspaceId, t.userId] }),
  index('profile_flags_user_idx').on(t.userId),
  check('profile_flags_appeal_status_check', sql`${t.appealStatus} IN ('none', 'pending', 'denied')`),
  check('profile_flags_appeal_time_check', sql`(${t.appealStatus} = 'none') = (${t.appealRequestedAt} IS NULL)`),
]);

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
  approvedAt: timestamp('approved_at', { withTimezone: true }),
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
  authenticationMethod: text('authentication_method').notNull().default('password'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('sessions_user_id_idx').on(t.userId),
  index('sessions_user_expires_idx').on(t.userId, t.expiresAt),
  index('sessions_device_id_idx').on(t.deviceId),
  index('sessions_expires_at_idx').on(t.expiresAt),
]);

export const devicesRelations = relations(devices, ({ one }) => ({
  user: one(users, { fields: [devices.userId], references: [users.id] }),
}));

export const passkeys = pgTable('passkeys', {
  id: text('id').primaryKey(),
  userId: uuid('user_id').notNull().references(() => users.id),
  name: text('name').notNull(),
  publicKey: text('public_key').notNull(),
  counter: bigint('counter', { mode: 'number' }).notNull(),
  transports: jsonb('transports').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index('passkeys_user_idx').on(t.userId)]);

// Challenges and step-up capabilities are one-use, expire, and bind to the
// durable session and exact operation. Never persist a bearer grant itself.
export const authenticationChallenges = pgTable('authentication_challenges', {
  id: uuid('id').primaryKey(),
  userId: uuid('user_id').references(() => users.id),
  sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'cascade' }),
  purpose: text('purpose').notNull(),
  challenge: text('challenge').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
}, (t) => [
  index('authentication_challenges_expiry_idx').on(t.expiresAt),
  index('authentication_challenges_session_idx').on(t.sessionId),
]);

// One pending registration code per address; the code itself is never stored.
export const emailVerifications = pgTable('email_verifications', {
  email: text('email').primaryKey(),
  codeHash: text('code_hash').notNull(),
  attempts: integer('attempts').default(0).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('email_verifications_expires_idx').on(t.expiresAt),
  check('email_verifications_attempts_check', sql`${t.attempts} >= 0`),
]);

export const stepUpGrants = pgTable('step_up_grants', {
  tokenHash: text('token_hash').primaryKey(),
  sessionId: uuid('session_id').notNull().references(() => sessions.id, { onDelete: 'cascade' }),
  purpose: text('purpose').notNull(),
  authentication: jsonb('authentication').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
}, (t) => [index('step_up_grants_session_idx').on(t.sessionId)]);

export const deviceDirectoryEvents = pgTable('device_directory_events', {
  userId: uuid('user_id').notNull().references(() => users.id),
  sequence: integer('sequence').notNull(),
  previousHash: text('previous_hash').notNull(),
  hash: text('hash').notNull(),
  event: jsonb('event').notNull(),
}, (t) => [primaryKey({ columns: [t.userId, t.sequence] })]);

export const historyRecovery = pgTable('history_recovery', {
  userId: uuid('user_id').primaryKey().references(() => users.id),
  generation: uuid('generation').notNull(),
  signingKey: text('signing_key').notNull(),
  encryptedSecret: text('encrypted_secret').notNull(),
  accessTokenHash: text('access_token_hash'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const historyRecoveryKeys = pgTable('history_recovery_keys', {
  userId: uuid('user_id').notNull().references(() => users.id),
  generation: uuid('generation').notNull(),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull(),
  keyCommitment: text('key_commitment').notNull(),
  ciphertext: text('ciphertext').notNull(),
}, (t) => [primaryKey({ columns: [t.userId, t.generation, t.channelId, t.version] })]);

// === Workspaces ===

export const workspaces = pgTable('workspaces', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  iconUrl: text('icon_url'),
  ownerId: uuid('owner_id').notNull().references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('workspaces_owner_id_idx').on(t.ownerId),
]);

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
  index('channels_workspace_type_idx').on(t.workspaceId, t.type),
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
  allowMaskCheck: check('category_role_permission_overrides_allow_mask_check', sql`${t.allowMask} >= 0 and (${t.allowMask} & ${sql.raw('-409728')}) = 0`),
  denyMaskCheck: check('category_role_permission_overrides_deny_mask_check', sql`${t.denyMask} >= 0 and (${t.denyMask} & ${sql.raw('-409728')}) = 0`),
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
  allowMaskCheck: check('channel_role_permission_overrides_allow_mask_check', sql`${t.allowMask} >= 0 and (${t.allowMask} & ${sql.raw('-409728')}) = 0`),
  denyMaskCheck: check('channel_role_permission_overrides_deny_mask_check', sql`${t.denyMask} >= 0 and (${t.denyMask} & ${sql.raw('-409728')}) = 0`),
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
  // Forum channels only: the post this event belongs to. It is part of the
  // signed v4 envelope, so the server can index by it but not rewrite it.
  postId: uuid('post_id'),
  idempotencyKey: text('idempotency_key'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  uniqueChannelIdempotency: unique().on(t.channelId, t.idempotencyKey),
  postFk: foreignKey({
    name: 'messages_post_id_fk',
    columns: [t.postId],
    foreignColumns: [t.id],
  }),
  channelCreatedIdx: index('messages_channel_created_idx').on(t.channelId, t.createdAt, t.id),
  postCreatedIdx: index('messages_post_created_idx').on(t.postId, t.createdAt, t.id).where(sql`${t.postId} is not null`),
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
  userCreatedIdx: index('message_bookmarks_user_created_idx').on(t.userId, t.createdAt, t.messageId),
}));

// === Forum ===

// One row per post (the message that started it). Sorting and moderation
// state live here so listing never needs to scan or decrypt message history.
export const forumPosts = pgTable('forum_posts', {
  messageId: uuid('message_id').primaryKey().references(() => messages.id),
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  authorId: uuid('author_id').notNull().references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull(),
  lastActivityAt: timestamp('last_activity_at', { withTimezone: true }).notNull(),
  replyCount: integer('reply_count').notNull().default(0),
  lockedAt: timestamp('locked_at', { withTimezone: true }),
  lockedBy: uuid('locked_by').references(() => users.id),
  resolvedAt: timestamp('resolved_at', { withTimezone: true }),
  resolvedBy: uuid('resolved_by').references(() => users.id),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
}, (t) => [
  unique('forum_posts_message_channel_unique').on(t.messageId, t.channelId),
  index('forum_posts_channel_activity_idx')
    .on(t.channelId, t.lastActivityAt.desc(), t.messageId.desc())
    .where(sql`${t.deletedAt} is null`),
  index('forum_posts_channel_created_idx')
    .on(t.channelId, t.createdAt.desc(), t.messageId.desc())
    .where(sql`${t.deletedAt} is null`),
  index('forum_posts_author_idx').on(t.authorId),
  check('forum_posts_reply_count_check', sql`${t.replyCount} >= 0`),
  check('forum_posts_activity_check', sql`${t.lastActivityAt} >= ${t.createdAt}`),
  check('forum_posts_locked_pair_check', sql`(${t.lockedAt} is null) = (${t.lockedBy} is null)`),
  check('forum_posts_resolved_pair_check', sql`(${t.resolvedAt} is null) = (${t.resolvedBy} is null)`),
]);

// Tag names are administrator-defined labels, visible to the server like
// channel names. They belong to the forum channel and go with it.
export const forumTags = pgTable('forum_tags', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').notNull().references(() => channels.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  position: integer('position').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  unique('forum_tags_channel_name_unique').on(t.channelId, t.name),
  unique('forum_tags_channel_id_unique').on(t.channelId, t.id),
  index('forum_tags_channel_position_idx').on(t.channelId, t.position),
  check('forum_tags_name_check', sql`char_length(${t.name}) between 1 and 20 and ${t.name} = btrim(${t.name})`),
  check('forum_tags_position_check', sql`${t.position} between 0 and 1000000`),
]);

// Both composite keys pin the tag and the post to the same channel.
export const forumPostTags = pgTable('forum_post_tags', {
  postId: uuid('post_id').notNull(),
  channelId: uuid('channel_id').notNull(),
  tagId: uuid('tag_id').notNull(),
}, (t) => [
  primaryKey({ name: 'forum_post_tags_pk', columns: [t.postId, t.tagId] }),
  foreignKey({
    name: 'forum_post_tags_post_fk',
    columns: [t.postId, t.channelId],
    foreignColumns: [forumPosts.messageId, forumPosts.channelId],
  }).onDelete('cascade'),
  foreignKey({
    name: 'forum_post_tags_tag_fk',
    columns: [t.channelId, t.tagId],
    foreignColumns: [forumTags.channelId, forumTags.id],
  }).onDelete('cascade'),
  index('forum_post_tags_tag_idx').on(t.channelId, t.tagId),
]);

export const forumPostReads = pgTable('forum_post_reads', {
  userId: uuid('user_id').notNull().references(() => users.id),
  postId: uuid('post_id').notNull().references(() => forumPosts.messageId, { onDelete: 'cascade' }),
  lastReadActivityAt: timestamp('last_read_activity_at', { withTimezone: true }).notNull(),
}, (t) => [
  primaryKey({ name: 'forum_post_reads_pk', columns: [t.userId, t.postId] }),
  index('forum_post_reads_post_idx').on(t.postId),
]);

// === DM ===

export const dmConversations = pgTable('dm_conversations', {
  id: uuid('id').primaryKey().defaultRandom(),
  channelId: uuid('channel_id').unique().notNull().references(() => channels.id),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  createdByIdx: index('dm_conversations_created_by_idx').on(t.createdBy),
}));

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
  index('attachment_uploads_uploader_expiry_idx').on(t.uploaderId, t.expiresAt),
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

export const mlsKeyPackages = pgTable('mls_key_packages', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull(),
  deviceId: uuid('device_id').notNull().references(() => devices.id),
  packageId: uuid('package_id').notNull(),
  keyPackage: text('key_package').notNull(),
  signature: text('signature').notNull(),
}, (t) => [primaryKey({ columns: [t.channelId, t.version, t.deviceId] }), unique('mls_package_id_unique').on(t.packageId)]);
export const mlsEpochs = pgTable('mls_epochs', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  version: integer('version').notNull(),
  transcript: text('transcript').notNull(),
  envelope: jsonb('envelope').notNull(),
}, (t) => [primaryKey({ columns: [t.channelId, t.version] })]);

export const channelDirectoryHeads = pgTable('channel_directory_heads', {
  channelId: uuid('channel_id').notNull().references(() => channels.id),
  userId: uuid('user_id').notNull().references(() => users.id),
  sequence: integer('sequence').notNull(),
}, (t) => [primaryKey({ columns: [t.channelId, t.userId] }),
  check('channel_directory_heads_sequence_check', sql`${t.sequence} between 0 and 8192`)]);
