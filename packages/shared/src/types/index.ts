// === User ===

export interface User {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  status: UserStatusType;
  createdAt: string;
}

export type UserStatusType = 'online' | 'idle' | 'dnd' | 'offline';

// === Auth ===

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  displayName: string;
  inviteToken?: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

// === Device ===

export interface Device {
  id: string;
  userId: string;
  name: string;
  identityKey: string; // RSA public key (PEM)
  createdAt: string;
  lastActiveAt: string | null;
  revokedAt: string | null;
}

export interface DeviceRegisterRequest {
  name: string;
  identityKey: string;
}

// === Workspace ===

export interface Workspace {
  id: string;
  name: string;
  iconUrl: string | null;
  ownerId: string;
  createdAt: string;
}

export interface WorkspaceCreateRequest {
  name: string;
  iconUrl?: string;
}

export interface WorkspaceMember {
  id: string;
  workspaceId: string;
  userId: string;
  user: User;
  roles: Role[];
  joinedAt: string;
}

// === Role ===

export interface Role {
  id: string;
  workspaceId: string;
  name: string;
  permissions: string; // bigint as string
  position: number;
}

// === Category ===

export interface Category {
  id: string;
  workspaceId: string;
  name: string;
  position: number;
  channels: Channel[];
}

export interface CategoryCreateRequest {
  name: string;
  position?: number;
}

// === Channel ===

export interface Channel {
  id: string;
  workspaceId: string;
  categoryId: string | null;
  name: string;
  type: 'text' | 'dm' | 'announcement';
  isPrivate: boolean;
  topic: string | null;
  position: number;
  createdAt: string;
  unreadCount?: number;
  lastReadMessageId?: string;
}

export interface ChannelCreateRequest {
  name: string;
  categoryId?: string;
  type?: 'text' | 'dm' | 'announcement';
  isPrivate?: boolean;
  topic?: string;
  position?: number;
}

export interface ChannelUpdateRequest {
  name?: string;
  categoryId?: string;
  topic?: string;
  position?: number;
  isPrivate?: boolean;
}

// === Message ===

export interface Message {
  id: string;
  channelId: string;
  authorId: string;
  author: User;
  deviceId: string;
  content: string; // decrypted plaintext (client-side)
  encryptedContent: string; // base64 encrypted
  contentNonce: string;
  type: 'message' | 'edit' | 'delete' | 'reaction' | 'system';
  refMessageId: string | null;
  refMessage?: Message;
  reactions: Reaction[];
  isPinned: boolean;
  idempotencyKey: string;
  createdAt: string;
}

export interface MessageCreateRequest {
  content: string; // plaintext (will be encrypted client-side)
  encryptedContent: string;
  contentNonce: string;
  refMessageId?: string;
  idempotencyKey: string;
  type?: 'message' | 'edit' | 'delete' | 'reaction' | 'system';
}

export interface MessageUpdateRequest {
  encryptedContent: string;
  contentNonce: string;
}

// === Reaction ===

export interface Reaction {
  emoji: string;
  count: number;
  userIds: string[];
}

export interface ReactionRequest {
  emoji: string;
}

// === Attachment ===

export interface Attachment {
  id: string;
  messageId: string;
  filenameEnc: string;
  mimeType: string;
  sizeBytes: number;
  storageKey: string;
  encryptionKey: string; // encrypted with channel key
  thumbnailKey: string | null;
  createdAt: string;
}

// === Channel Key ===

export interface ChannelKey {
  id: string;
  channelId: string;
  version: number;
  encryptedKey: string; // encrypted with device public key
  deviceId: string;
  createdAt: string;
}

export interface ChannelKeyDistributeRequest {
  channelId: string;
  keys: Array<{
    deviceId: string;
    encryptedKey: string;
  }>;
  version: number;
}

// === Read Position ===

export interface ReadPosition {
  userId: string;
  channelId: string;
  lastReadMessageId: string | null;
  updatedAt: string;
}

// === DM ===

export interface DmConversation {
  id: string;
  channelId: string;
  members: User[];
}

// === Audit ===

export interface AuditLog {
  id: string;
  actorId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  details: Record<string, unknown> | null;
  prevHash: string | null;
  hash: string;
  createdAt: string;
}

// === WebSocket Events ===

export interface WsMessageNew {
  message: Message;
}

export interface WsMessageEdited {
  message: Message;
}

export interface WsMessageDeleted {
  messageId: string;
  channelId: string;
}

export interface WsTypingUpdate {
  channelId: string;
  userId: string;
  isTyping: boolean;
}

export interface WsPresenceChanged {
  userId: string;
  status: UserStatusType;
}

export interface WsMemberJoined {
  channelId: string;
  user: User;
}

export interface WsMemberLeft {
  channelId: string;
  userId: string;
}

export interface WsChannelCreated {
  channel: Channel;
}

export interface WsKeyRotated {
  channelId: string;
  version: number;
}

// === API Responses ===

export interface PaginatedResponse<T> {
  data: T[];
  hasMore: boolean;
  cursor: string | null;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
}
