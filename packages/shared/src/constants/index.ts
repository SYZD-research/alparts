export const Permissions = {
  SEND_MESSAGES: 1 << 0,
  EDIT_MESSAGES: 1 << 1,
  DELETE_MESSAGES: 1 << 2,
  ADD_REACTIONS: 1 << 3,
  MENTION_EVERYONE: 1 << 4,
  PIN_MESSAGES: 1 << 5,
  VIEW_CHANNELS: 1 << 6,
  MANAGE_CHANNELS: 1 << 7,
  MANAGE_MEMBERS: 1 << 8,
  KICK_MEMBERS: 1 << 9,
  BAN_MEMBERS: 1 << 10,
  MANAGE_WORKSPACE: 1 << 11,
  MANAGE_ROLES: 1 << 12,
  VIEW_AUDIT_LOG: 1 << 13,
  ATTACH_FILES: 1 << 14,
  MANAGE_WEBHOOKS: 1 << 15,
  MANAGE_BOTS: 1 << 16,
} as const;

export type Permission = keyof typeof Permissions;

export const DefaultRoles = {
  Owner: Object.values(Permissions).reduce((a, b) => a | b, 0),
  Administrator: Object.values(Permissions).reduce((a, b) => a | b, 0),
  SecurityManager:
    Permissions.VIEW_CHANNELS |
    Permissions.VIEW_AUDIT_LOG |
    Permissions.MANAGE_MEMBERS,
  Member:
    Permissions.SEND_MESSAGES |
    Permissions.EDIT_MESSAGES |
    Permissions.DELETE_MESSAGES |
    Permissions.ADD_REACTIONS |
    Permissions.PIN_MESSAGES |
    Permissions.VIEW_CHANNELS |
    Permissions.ATTACH_FILES,
  Guest:
    Permissions.SEND_MESSAGES |
    Permissions.VIEW_CHANNELS,
  Integration:
    Permissions.SEND_MESSAGES |
    Permissions.VIEW_CHANNELS |
    Permissions.ATTACH_FILES,
} as const;

export const ChannelType = {
  TEXT: 'text',
  DM: 'dm',
  ANNOUNCEMENT: 'announcement',
} as const;

export const MessageType = {
  MESSAGE: 'message',
  EDIT: 'edit',
  DELETE: 'delete',
  REACTION: 'reaction',
  SYSTEM: 'system',
} as const;

export const UserStatus = {
  ONLINE: 'online',
  IDLE: 'idle',
  DND: 'dnd',
  OFFLINE: 'offline',
} as const;

export const MAX_MESSAGE_LENGTH = 4000;
export const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
export const MESSAGES_PER_PAGE = 50;
