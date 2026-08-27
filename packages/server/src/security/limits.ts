/** Phase-one limits keep fanout and authorization work predictably bounded. */
export const MAX_ACTIVE_DEVICES_PER_USER = 8;
export const MAX_WORKSPACE_MEMBERS = 50;
export const MAX_CHANNELS_PER_WORKSPACE = 100;
export const MAX_CATEGORIES_PER_WORKSPACE = 50;
export const MAX_KEY_RECIPIENTS = MAX_ACTIVE_DEVICES_PER_USER * MAX_WORKSPACE_MEMBERS;
