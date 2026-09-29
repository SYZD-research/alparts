/** Phase-one limits keep fanout and authorization work predictably bounded. */
export const MAX_ACTIVE_DEVICES_PER_USER = 8;
export const MAX_ACTIVE_SESSIONS_PER_USER = 16;
/** A passkey sign-in counts as a fresh assertion for device enrollment only this long. */
export const PASSKEY_DEVICE_ENROLLMENT_WINDOW_MS = 10 * 60 * 1000;
export const MAX_WORKSPACE_MEMBERS = 50;
export const MAX_WORKSPACES_OWNED_PER_USER = 20;
export const MAX_WORKSPACE_MEMBERSHIPS_PER_USER = 50;
export const MAX_CHANNELS_PER_WORKSPACE = 100;
export const MAX_DMS_PER_WORKSPACE = 200;
export const MAX_DMS_PER_USER_PER_WORKSPACE = 50;
export const MAX_TOTAL_CHANNELS_PER_WORKSPACE = MAX_CHANNELS_PER_WORKSPACE + MAX_DMS_PER_WORKSPACE;
export const MAX_CATEGORIES_PER_WORKSPACE = 50;
export const MAX_ROLES_PER_WORKSPACE = 32;
export const MAX_ROLE_ASSIGNMENTS_PER_MEMBER = 16;
export const MAX_ACTIVE_INVITATIONS_PER_WORKSPACE = 100;
export const MAX_RETAINED_INVITATIONS_PER_WORKSPACE = 1_000;
export const INVITATION_RETENTION_DAYS = 90;
export const MAX_CONCURRENT_PASSWORD_WORK = 2;
export const MAX_PENDING_PASSWORD_WORK = 16;
export const PASSWORD_WORK_WAIT_MS = 5_000;
export const PASSWORD_WORK_EXECUTION_MS = 30_000;
export const MAX_PENDING_AUDIT_COMMITS = 64;
export const AUDIT_COMMIT_WAIT_MS = 30_000;
export const MAX_BOOKMARKS_PER_USER = 1_000;
export const MAX_PINS_PER_CHANNEL = 1_000;
export const MAX_REACTION_EMOJIS_PER_MESSAGE = 20;
export const MAX_REACTIONS_PER_USER_PER_MESSAGE = 20;
export const MAX_REACTIONS_PER_MESSAGE = MAX_WORKSPACE_MEMBERS * MAX_REACTIONS_PER_USER_PER_MESSAGE;
export const MAX_PENDING_UPLOADS_PER_USER = 16;
export const MAX_PENDING_UPLOADS_PER_WORKSPACE = 200;
export const MAX_KEY_RECIPIENTS = MAX_ACTIVE_DEVICES_PER_USER * MAX_WORKSPACE_MEMBERS;
export const MAX_KEY_DELIVERIES_PER_FETCH = MAX_KEY_RECIPIENTS * 2;
export const MAX_KEY_VERSION_LOOKUP_IDS = 64;
/** Bounded rollout bridge for browser tabs opened before versioned lookup. */
export const MAX_LEGACY_KEY_VERSION_LOOKUP_IDS = 16;
// Active and pending epochs can each expose MAX_KEY_RECIPIENTS immutable repair
// candidates. Retired epochs expose only their one accepted delivery/device.
export const MAX_KEY_DELIVERIES_PER_HISTORY_BATCH = MAX_KEY_DELIVERIES_PER_FETCH
  + MAX_KEY_VERSION_LOOKUP_IDS;
export const MAX_DEVICE_DIRECTORY_ENTRIES = MAX_KEY_RECIPIENTS;
export const MAX_DEVICE_DIRECTORY_LOOKUP_IDS = 64;
