// === User ===

export interface User {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  status: UserStatusType;
  createdAt: string;
}

/** Public profile fields safe to embed in channel message payloads. */
export type PublicUser = Omit<User, 'email'>;

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
  user: User;
}

// === Device ===

export interface Device {
  approvedAt?: string | null;
  id: string;
  userId: string;
  name: string;
  identityKey: string; // versioned JSON bundle: RSA-OAEP encryption + P-256 signing JWKs
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
  user: PublicUser;
  /** An administrator of this workspace marked the profile; show it only after confirmation. */
  profileFlagged?: boolean;
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

export type ChannelKind = 'text' | 'dm' | 'announcement' | 'voice' | 'forum';

export interface Channel {
  id: string;
  workspaceId: string;
  categoryId: string | null;
  name: string;
  type: ChannelKind;
  isPrivate: boolean;
  keyRotationRequired?: boolean;
  topic: string | null;
  position: number;
  createdAt: string;
  unreadCount?: number;
  lastReadMessageId?: string;
}

export interface ChannelCreateRequest {
  name: string;
  categoryId?: string;
  type?: Exclude<ChannelKind, 'dm'>;
  isPrivate?: boolean;
  topic?: string;
  position?: number;
}

export interface ChannelUpdateRequest {
  name?: string;
  categoryId?: string | null;
  topic?: string;
  position?: number;
  isPrivate?: boolean;
}

// === Message ===

export interface Message {
  id: string;
  channelId: string;
  authorId: string;
  author: PublicUser;
  deviceId: string | null;
  content: string; // decrypted plaintext (client-side)
  encryptedContent: string; // base64 encrypted
  contentNonce: string;
  keyVersion: number;
  signature: string | null;
  /** Authenticated for protocol v3; null identifies legacy v2 envelopes. */
  broadcastMention?: boolean | null;
  type: 'message' | 'edit' | 'delete' | 'reaction' | 'system';
  refMessageId: string | null;
  /**
   * Forum channels only: the post this event belongs to, authenticated by the
   * v4 envelope. Null on the event that starts a post and outside forums.
   */
  postId?: string | null;
  refMessage?: Message;
  reactions: Reaction[];
  isPinned: boolean;
  attachments?: Attachment[];
  idempotencyKey: string;
  createdAt: string;
}

export interface MessageCreateRequest {
  content: string; // plaintext (will be encrypted client-side)
  encryptedContent: string;
  contentNonce: string;
  deviceId: string;
  keyVersion: number;
  signature: string;
  broadcastMention: boolean;
  refMessageId?: string;
  idempotencyKey: string;
  type?: 'message' | 'edit' | 'delete' | 'reaction' | 'system';
}

export interface MessageUpdateRequest {
  encryptedContent: string;
  contentNonce: string;
}

// === Forum ===

/** Administrator-defined label. Names are shared like channel names, not encrypted. */
export interface ForumTag {
  id: string;
  channelId: string;
  name: string;
  position: number;
}

export interface ForumPostState {
  postId: string;
  channelId: string;
  authorId: string;
  createdAt: string;
  lastActivityAt: string;
  replyCount: number;
  locked: boolean;
  resolved: boolean;
  tagIds: string[];
  isPinned: boolean;
  /** New replies since this viewer last opened the post. */
  unread: boolean;
}

/**
 * A post as listed: the event that started it, its most recent edit (if any)
 * so the current title can be shown, and server-maintained state.
 */
export interface ForumPostSummary {
  root: Message;
  latestEdit: Message | null;
  state: ForumPostState;
}

/** What the viewer may do in this forum, from their effective channel permissions. */
export interface ForumViewerCapabilities {
  canCreatePosts: boolean;
  canReply: boolean;
  canManage: boolean;
  canPin: boolean;
  canAttach: boolean;
}

/** Broadcast to every viewer; each client keeps its own unread flag. */
export interface WsForumPostUpdated {
  channelId: string;
  state: Omit<ForumPostState, 'unread'>;
}

export interface WsForumPostRemoved {
  channelId: string;
  postId: string;
}

export interface WsForumTagsUpdated {
  channelId: string;
  tags: ForumTag[];
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
  /** Nullable only while reading legacy rows; clients must reject missing sender metadata. */
  channelId: string | null;
  keyVersion: number | null;
  deviceId: string | null;
  signature: string | null;
  filenameEnc: string;
  mimeType: string;
  dangerousMime: boolean;
  downloadPolicy: 'attachment-only';
  sizeBytes: number;
  ciphertextSizeBytes: number;
  plaintextSizeBytes: number | null;
  chunkCount: number;
  wrappedKey: string; // file key encrypted with the channel key
  contentNonce: string;
  cryptoManifest: {
    version: 1;
    algorithm: 'AES-256-GCM';
    nonceStrategy: 'prefix-counter-be32';
    noncePrefix: string;
    aadVersion: 1;
    plaintextSize: number;
    chunkPlaintextBytes: number;
    authenticationTagBytes: number;
    chunkCount: number;
    uploadId: string;
    messageId: string;
    aadFormat: string;
  };
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
  keyCommitment: string;
  distributorDeviceId: string;
  signature: string;
  createdAt: string;
}

export interface ChannelKeyDistributeRequest {
  channelId: string;
  keyCommitment: string;
  keys: Array<{
    deviceId: string;
    encryptedKey: string;
    signature: string;
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

export type NotificationLevel = 'all' | 'mentions' | 'none';

export interface ChannelPreference {
  channelId: string;
  favorite: boolean;
  muted: boolean;
  hidden: boolean;
  notificationLevel: NotificationLevel;
  updatedAt: string | null;
}

export interface ChannelReadState extends ChannelPreference {
  lastReadMessageId: string | null;
  latestMessageId: string | null;
  unreadCount: number;
}

export interface MessageBookmark {
  messageId: string;
  channelId: string;
  createdAt: string;
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

/** `channel-restarted`: sent to managers when a member restarted a channel whose history no device could show. */
export type AttentionNotificationKind = 'mention' | 'reply' | 'channel-restarted' | 'profile-appeal';

/** A content-free realtime notification. Message plaintext is never included. */
export interface WsAttentionNotification {
  notificationId: string;
  workspaceId: string;
  /** null only for 'profile-appeal', which concerns a member rather than a channel. */
  channelId: string | null;
  /** Forum channels: the post the notification belongs to. */
  postId?: string | null;
  kind: AttentionNotificationKind;
}

// === Profiles ===

export type ProfileAppealStatus = 'none' | 'pending' | 'denied';

export interface MemberProfile {
  userId: string;
  displayName: string;
  avatarUrl: string | null;
  bio: string | null;
  flagged: boolean;
  /** Present only for viewers who may manage the warning. */
  appealStatus?: ProfileAppealStatus;
  canManageFlag: boolean;
}

export interface OwnProfile {
  displayName: string;
  avatarUrl: string | null;
  bio: string | null;
  /** The one lifetime request to lift a warning has been used. */
  appealUsed: boolean;
  flags: Array<{
    workspaceId: string;
    workspaceName: string;
    appealStatus: ProfileAppealStatus;
    /** Changed since the warning, and the lifetime request is unused. */
    canAppeal: boolean;
  }>;
}

export interface ProfileFlagEntry {
  userId: string;
  displayName: string;
  flaggedAt: string;
  appealStatus: ProfileAppealStatus;
  appealRequestedAt: string | null;
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
