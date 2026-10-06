import { solveLoginChallenge } from './login-challenge';
import type {
  MemberProfile,
  OwnProfile,
  ProfileFlagEntry,
  Attachment,
  Category,
  Channel,
  ChannelPreference,
  ChannelReadState,
  Device,
  ForumPostState,
  ForumPostSummary,
  ForumTag,
  ForumViewerCapabilities,
  Message,
  MessageBookmark,
  NotificationLevel,
  ReadPosition,
  Reaction,
  User,
  UserStatusType,
  Workspace,
  WorkspaceMember,
} from '@alparts/shared';
import { withExpectedAuthorizationRevision } from './role-authorization-revision';

const API_BASE = '/api';
export const API_REQUEST_DEADLINE_MS = 60_000;

export function createApiRequestDeadline(
  parentSignal: AbortSignal | null | undefined,
  timeoutMs = API_REQUEST_DEADLINE_MS,
): { signal: AbortSignal; dispose: () => void } {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > API_REQUEST_DEADLINE_MS) {
    throw new Error('Invalid API request deadline');
  }
  const controller = new AbortController();
  const forwardAbort = () => controller.abort(parentSignal?.reason ?? new Error('API_REQUEST_ABORTED'));
  if (parentSignal?.aborted) forwardAbort();
  else parentSignal?.addEventListener('abort', forwardAbort, { once: true });
  const timeout = setTimeout(() => controller.abort(new Error('API_REQUEST_TIMEOUT')), timeoutMs);
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timeout);
      parentSignal?.removeEventListener('abort', forwardAbort);
    },
  };
}

interface ApiErrorPayload {
  challenge?: unknown;
  purpose?: string;
  error?: string;
  message?: string;
  statusCode?: number;
}

const API_ERROR_MESSAGES_BY_CODE: Record<string, string> = {
  DEVICE_LIMIT_REACHED: '登録済みの端末が上限に達しています。不要な端末の登録を解除してください。',
  SESSION_LIMIT_REACHED: 'ログイン中の端末が上限に達しています。別の端末からログアウトしてお試しください。',
  DEVICE_STEP_UP_REQUIRED: 'この端末を追加するには、もう一度ログインしてください。',
  DEVICE_APPROVAL_REQUIRED: 'この端末はまだ承認されていません。承認済みの端末から承認してください。',
  STEP_UP_REQUIRED: '続けるには本人確認が必要です。',
  UPDATE_REQUIRED: 'アプリを更新してから、もう一度お試しください。',
  STALE_PREVIEW: '他の変更と重なりました。表示を更新してもう一度お試しください。',
  STALE_OVERRIDE: '他の変更と重なりました。表示を更新してもう一度お試しください。',
  DIRECTORY_CONFLICT: '端末の一覧が更新されました。表示を更新してもう一度お試しください。',
  IDEMPOTENCY_CONFLICT: '同じ操作がすでに行われています。表示を更新してください。',
  PASSKEY_REQUIRED: 'パスワードでのログインをオフにするには、先にパスキーを追加してください。',
};

/** Fixed, local wording for an HTTP failure. */
export function apiErrorMessage(status: number, code?: string): string {
  if (code && API_ERROR_MESSAGES_BY_CODE[code]) return API_ERROR_MESSAGES_BY_CODE[code];
  if (status === 400) return '入力内容を確認してください。';
  if (status === 401) return 'ログインし直してください。';
  if (status === 403) return 'この操作を行う権限がありません。';
  if (status === 404) return '対象が見つかりません。表示を更新してください。';
  if (status === 409) return '他の変更と重なりました。表示を更新してもう一度お試しください。';
  if (status === 410) return 'アプリを更新してから、もう一度お試しください。';
  if (status === 413) return 'サイズが大きすぎます。';
  if (status === 428) return '続けるには本人確認が必要です。';
  if (status === 429) return '操作が多すぎます。しばらく待ってからお試しください。';
  if (status === 503) return '現在混み合っています。しばらく待ってからお試しください。';
  if (status >= 500) return 'サーバーで問題が発生しました。しばらく待ってからお試しください。';
  return '操作を完了できませんでした。もう一度お試しください。';
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(message: string, status: number, code?: string, readonly retryAfterSeconds?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || null;
  }
}

// Retain fetch's TypeError contract so existing transfer/message retries still
// treat a lost connection as transient, without confusing it with an HTTP error.
export class ApiConnectionError extends TypeError {
  constructor() {
    super('Could not connect to server');
    this.name = 'ApiConnectionError';
  }
}

export interface AuthSession {
  id: string;
  deviceId: string | null;
  deviceInfo: Record<string, unknown> | null;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export interface DirectMessageMember {
  id: string;
  displayName: string;
  avatarUrl: string | null;
  status: UserStatusType;
  createdAt: string;
}

export interface DirectMessageConversation {
  id: string;
  channelId: string;
  workspaceId: string;
  createdAt: string;
  members: DirectMessageMember[];
}

export interface ChannelMemberSummary {
  id: string;
  displayName: string;
  avatarUrl: string | null;
  status: UserStatusType;
}

export interface ChannelMutationInput {
  name?: string;
  topic?: string;
  categoryId?: string | null;
  position?: number;
  isPrivate?: boolean;
}

export interface CategoryMutationInput {
  name?: string;
  position?: number;
}

export interface WorkspaceRole {
  id: string;
  workspaceId: string;
  name: string;
  permissions: string;
  permissionMask: number;
  position: number;
  standard: boolean;
  createdAt: string;
}

export type InvitationStatus = 'active' | 'used' | 'revoked' | 'expired';

export interface WorkspaceInvitation {
  id: string;
  workspaceId: string;
  role: Pick<WorkspaceRole, 'id' | 'name' | 'permissions' | 'position'> | null;
  email: string | null;
  createdBy: string;
  expiresAt: string;
  usedAt: string | null;
  usedBy: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
  createdAt: string;
  status: InvitationStatus;
}

export interface CreatedWorkspaceInvitation extends WorkspaceInvitation {
  token: string;
}

export interface AcceptedInvitation {
  invitationId: string;
  workspaceId: string;
  roleId: string;
}

export type ChannelKeyEpochStatus = 'pending' | 'active' | 'retired' | 'aborted';

export interface ChannelKeyDelivery {
  deliveryId: string;
  version: number;
  encryptedKey: string;
  keyCommitment: string;
  distributorDeviceId: string;
  distributorIdentityKey: string;
  signature: string;
  epochStatus: ChannelKeyEpochStatus;
  confirmedAt: string | null;
  createdAt: string;
}

export interface ChannelKeyRecipientState {
  protocolVersion?: number;
  pendingProtocolVersion?: number | null;
  /** Currently active, writable epoch. Zero means no active epoch exists. */
  currentVersion: number;
  keyCommitment: string | null;
  /** A pending epoch is never writable until the server activates it. */
  pendingVersion: number | null;
  pendingKeyCommitment: string | null;
  pendingInvalid: boolean;
  nextVersion: number;
  rotationRequired: boolean;
  /** No authorized non-revoked device can decrypt the old active epoch. */
  historyRecoveryRequired: boolean;
  canRotate: boolean;
  canAbortPending: boolean;
  distributedDeviceIds: string[];
  pendingAcknowledgedDeviceIds: string[];
  /** Omitted by older servers, where every pending recipient was required. */
  pendingRequiredDeviceIds?: string[];
  recipients: Array<{ deviceId: string; userId: string; identityKey: string }>;
}

export interface PermissionReason {
  source: 'role';
  roleId: string;
  roleName: string;
}

export interface PermissionDetail {
  permission: string;
  value: number;
  allowed: boolean;
  reasons: PermissionReason[];
}

export interface EffectivePermissions {
  workspaceId: string;
  userId: string;
  permissionMask: number;
  effectivePermissions: string;
  roles: WorkspaceRole[];
  permissionDetails: PermissionDetail[];
}

export interface AffectedRoleMember {
  userId: string;
  before: EffectivePermissions;
  after: EffectivePermissions;
  gained: string[];
  lost: string[];
}

export type RolePreviewInput =
  | { operation: 'role.update'; roleId: string; permissions: number }
  | { operation: 'role.delete'; roleId: string }
  | { operation: 'role.assign'; roleId: string; userId: string }
  | { operation: 'role.unassign'; roleId: string; userId: string };

export interface RoleChangePreview {
  workspaceId: string;
  operation: RolePreviewInput['operation'];
  authorizationRevision: string;
  affectedMembers: AffectedRoleMember[];
  affectedUserIds: string[];
  lostAccessUserIds: string[];
  gainedAccessUserIds: string[];
  requiresKeyRotation: boolean;
}

export interface RoleUpdateResult {
  role: WorkspaceRole;
  affectedMembers: AffectedRoleMember[];
  lostAccessUserIds: string[];
  gainedAccessUserIds: string[];
  allChannelIds: string[];
  keyedChannelIds: string[];
}

export interface RoleAssignmentResult {
  workspaceId: string;
  userId: string;
  roleId: string;
  action: 'assign' | 'unassign';
  changed: boolean;
  before: EffectivePermissions;
  after: EffectivePermissions;
  lostAccessUserIds: string[];
  gainedAccessUserIds: string[];
  allChannelIds: string[];
  keyedChannelIds: string[];
}

export type PermissionOverrideTarget = 'category' | 'channel';

export interface PermissionOverride {
  workspaceId: string;
  targetId: string;
  roleId: string;
  allowMask: number;
  denyMask: number;
  revision: number;
  updatedAt: string;
}

export interface PermissionOverridePreviewValue {
  workspaceId: string;
  targetId: string;
  roleId: string;
  allowMask: number;
  denyMask: number;
  revision: number;
}

export interface ChannelViewerEffect {
  channelId: string;
  lostUserIds: string[];
  gainedUserIds: string[];
  rotationRequired: boolean;
}

export type PermissionOverridePreviewInput =
  | { operation: 'upsert'; roleId: string; allowMask: number; denyMask: number }
  | { operation: 'delete'; roleId: string };

export interface PermissionOverridePreview {
  target: PermissionOverrideTarget;
  workspaceId: string;
  targetId: string;
  roleId: string;
  operation: PermissionOverridePreviewInput['operation'];
  currentRevision: number;
  authorizationRevision: string;
  before: PermissionOverride | null;
  after: PermissionOverridePreviewValue | null;
  roomEffects: ChannelViewerEffect[];
}

export interface PermissionOverrideWriteInput {
  allowMask: number;
  denyMask: number;
  expectedRevision: number;
  expectedAuthorizationRevision: string;
}

export interface PermissionOverrideDeleteInput {
  expectedRevision: number;
  expectedAuthorizationRevision: string;
}

export interface PermissionOverrideMutationResult {
  override: PermissionOverride;
  authorizationRevision: string;
  roomEffects: ChannelViewerEffect[];
}

export interface PermissionOverrideDeleteResult {
  workspaceId: string;
  target: PermissionOverrideTarget;
  targetId: string;
  roleId: string;
  deleted: true;
  authorizationRevision: string;
  roomEffects: ChannelViewerEffect[];
}

export type ChannelPermissionReason =
  | { source: 'role'; effect: 'allow'; roleId: string; roleName: string }
  | { source: 'category' | 'channel'; effect: 'allow' | 'deny'; roleId: string }
  | { source: 'workspace-owner'; effect: 'allow' }
  | { source: string; effect?: string; roleId?: string; roleName?: string };

export interface ChannelEffectivePermissions {
  workspaceId: string;
  channelId: string;
  userId: string;
  effectivePermissions: string;
  permissionMask: number;
  workspacePermissionMask: number;
  visible: boolean;
  privateMembershipRequired: boolean;
  privateMember: boolean;
  ownerProtected: boolean;
  roles: Array<{ id: string; name: string; permissions: number; position: number }>;
  permissionDetails: Array<{
    permission: string;
    value: number;
    allowed: boolean;
    reasons: ChannelPermissionReason[];
  }>;
}

export interface AttachmentUploadReservation {
  uploadId: string;
  reused: boolean;
  expiresAt: string;
  chunkPlaintextBytes: number;
  chunkCiphertextBytes: number;
  authenticationTagBytes: number;
  maxPlaintextBytes: number;
  maxChunkCount: number;
  crypto: {
    version: 1;
    algorithm: 'AES-256-GCM';
    nonceStrategy: 'prefix-counter-be32';
    noncePrefixBytes: number;
    aadVersion: 1;
    aadFormat: string;
  };
}

export interface AttachmentUploadCreateInput {
  messageId: string;
  filenameEnc: string;
  mimeType: string;
  idempotencyKey: string;
}

export interface AttachmentUploadStatus {
  uploadId: string;
  messageId: string;
  expiresAt: string;
  uploadedIndexes: number[];
  chunks: Array<{ index: number; ciphertextSizeBytes: number }>;
}

export interface AttachmentChunkUploadResult {
  uploadId: string;
  index: number;
  ciphertextSizeBytes: number;
  replaced: boolean;
}

export interface AttachmentFinalizeInput {
  deviceId: string;
  keyVersion: number;
  signature: string;
  chunkCount: number;
  wrappedKey: string;
  cryptoManifest: {
    version: 1;
    algorithm: 'AES-256-GCM';
    nonceStrategy: 'prefix-counter-be32';
    noncePrefix: string;
    aadVersion: 1;
    plaintextSize: number;
  };
}

export interface AttachmentUploadCancellation {
  uploadId: string;
  cancelled: true;
  alreadyAbsent: boolean;
  workspaceId?: string;
  messageId?: string;
}

export interface AuditLogEntry {
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

export interface AuditLogPage {
  data: AuditLogEntry[];
  hasMore: boolean;
  cursor: string | null;
}

export interface AuditIntegrityStatus {
  valid: boolean;
}

interface SuccessResponse {
  success: true;
}

function browserSessionInfo(): Record<string, string> {
  if (typeof navigator === 'undefined') return {};
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return {
    platform: (nav.userAgentData?.platform || navigator.platform || 'Web').slice(0, 80),
    browser: navigator.userAgent.slice(0, 200),
    language: navigator.language.slice(0, 32),
  };
}


/**
 * Path parameters are server-issued identifiers. Every path segment must be a
 * plain unreserved token so an unexpected value cannot traverse or re-route.
 */
export function assertSafeApiPath(path: string): void {
  const [pathname] = path.split('?', 1);
  // Percent-encoded segments (e.g. reaction emoji) are allowed; raw separators are not.
  let decoded: string[];
  try {
    decoded = pathname.split('/').map((segment) => decodeURIComponent(segment));
  } catch {
    throw new Error('INVALID_API_PATH');
  }
  const segments = pathname.split('/');
  if (
    segments[0] !== ''
    || segments.length < 2
    || segments.slice(1).some((segment, index) => (
      !/^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$/.test(segment)
      || ['.', '..'].includes(decoded[index + 1])
      || /[/?#\\]/.test(decoded[index + 1])
    ))
  ) {
    throw new Error('INVALID_API_PATH');
  }
}

class ApiService {
  private stepUpHandler: ((purpose: string, signal?: AbortSignal | null) => Promise<string>) | null = null;
  setStepUpHandler(handler: (purpose: string, signal?: AbortSignal | null) => Promise<string>) { this.stepUpHandler = handler; }
  securityRequest<T>(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> {
    return this.request<T>(path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }

  private unauthorizedHandler: (() => void) | null = null;

  setUnauthorizedHandler(handler: () => void): void {
    this.unauthorizedHandler = handler;
  }

  private async fetchResponse(path: string, options: RequestInit = {}): Promise<Response> {
    assertSafeApiPath(path);
    const headers = new Headers(options.headers);
    if (options.body !== undefined && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    let response: Response;
    try {
      response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
        credentials: 'same-origin',
      });
    } catch (error) {
      if (options.signal?.aborted) throw error;
      throw new ApiConnectionError();
    }

    if (!response.ok) {
      // An unauthenticated startup probe is normal on a new installation.
      // loadUser handles it; it must not claim a never-created session expired.
      if (response.status === 401 && path !== '/auth/login' && path !== '/auth/me') {
        queueMicrotask(() => this.unauthorizedHandler?.());
      }
      const raw = await response.json().catch(() => null) as unknown;
      const error: ApiErrorPayload = raw && typeof raw === 'object' ? raw as ApiErrorPayload : {};
      if (response.status === 428 && error.error === 'STEP_UP_REQUIRED' && error.purpose && this.stepUpHandler && !headers.has('X-Alparts-Step-Up')) {
        const token = await this.stepUpHandler(error.purpose, options.signal);
        headers.set('X-Alparts-Step-Up', token);
        return this.fetchResponse(path, { ...options, headers });
      }
      if (path === '/auth/login' && response.status === 428 && error.error === 'LOGIN_CHALLENGE_REQUIRED' && !headers.has('X-Alparts-Login-Proof')) {
        headers.set('X-Alparts-Login-Proof', await solveLoginChallenge(error.challenge, options.signal));
        return this.fetchResponse(path, { ...options, headers });
      }
      const code = typeof error.error === 'string' ? error.error : undefined;
      // The server's own message text is never shown: a compromised or
      // misconfigured server must not be able to place arbitrary text in the UI.
      throw new ApiError(
        apiErrorMessage(response.status, code),
        response.status,
        code,
        Number(response.headers.get('Retry-After')) || undefined,
      );
    }

    return response;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const deadline = createApiRequestDeadline(options.signal);
    try {
      const response = await this.fetchResponse(path, { ...options, signal: deadline.signal });
      return await response.json() as T;
    } finally {
      deadline.dispose();
    }
  }

  private async requestArrayBuffer(path: string, options: RequestInit = {}): Promise<ArrayBuffer> {
    const deadline = createApiRequestDeadline(options.signal);
    try {
      const response = await this.fetchResponse(path, { ...options, signal: deadline.signal });
      return await response.arrayBuffer();
    } finally {
      deadline.dispose();
    }
  }

  // Auth
  async register(email: string, password: string, displayName: string, inviteToken: string) {
    return this.request<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, displayName, inviteToken }),
    });
  }

  async login(email: string, password: string) {
    return this.request<{ user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, deviceInfo: browserSessionInfo() }),
    });
  }

  async logout() {
    return this.request<SuccessResponse>('/auth/logout', { method: 'POST' });
  }

  async reauthenticate(password: string) {
    return this.request<User>('/auth/reauthenticate', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  async getMe() {
    return this.request<User>('/auth/me');
  }

  async getSessions() {
    return this.request<AuthSession[]>('/auth/sessions');
  }

  async revokeSession(id: string) {
    return this.request<SuccessResponse>(`/auth/sessions/${id}`, { method: 'DELETE' });
  }

  async revokeAllSessions() {
    return this.request<SuccessResponse & { revoked: number }>('/auth/sessions', { method: 'DELETE' });
  }

  /** Needs an identity confirmation; every other login of the account ends. */
  async changePassword(newPassword: string) {
    return this.request<SuccessResponse & { revoked: number }>('/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ newPassword }),
    });
  }

  async getPasswordLogin() {
    return this.request<{ enabled: boolean }>('/auth/password-login');
  }

  /** Needs an identity confirmation; turning it off needs a passkey. */
  async setPasswordLogin(enabled: boolean) {
    return this.request<SuccessResponse & { enabled: boolean; revoked: number }>('/auth/password-login', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
  }

  // Workspaces
  async getWorkspaces() {
    return this.request<Workspace[]>('/workspaces');
  }

  async createWorkspace(name: string) {
    return this.request<Workspace>('/workspaces', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async getWorkspace(id: string) {
    return this.request<Workspace>(`/workspaces/${id}`);
  }

  async getWorkspaceMembers(id: string) {
    return this.request<WorkspaceMember[]>(`/workspaces/${id}/members`);
  }

  // Profiles
  async getOwnProfile() {
    return this.request<OwnProfile>('/profile');
  }

  async updateOwnProfile(input: { displayName?: string; bio?: string }) {
    return this.request<OwnProfile>('/profile', { method: 'PATCH', body: JSON.stringify(input) });
  }

  async uploadAvatar(png: Blob) {
    return this.request<{ avatarUrl: string }>('/profile/avatar', {
      method: 'PUT',
      body: png,
      headers: { 'Content-Type': 'image/png' },
    });
  }

  async removeAvatar() {
    return this.request<{ success: boolean }>('/profile/avatar', { method: 'DELETE' });
  }

  /** Only server-issued avatar paths are fetched. */
  async getAvatarBytes(avatarUrl: string) {
    const match = /^\/api(\/users\/[0-9a-f-]{36}\/avatar\/[0-9a-f-]{36})$/.exec(avatarUrl);
    if (!match) throw new Error('INVALID_AVATAR_URL');
    return this.requestArrayBuffer(match[1]);
  }

  async getMemberProfile(workspaceId: string, userId: string) {
    return this.request<MemberProfile>(`/workspaces/${workspaceId}/members/${userId}/profile`);
  }

  async getWarnedUsers(workspaceId: string) {
    return this.request<{ userIds: string[]; complete: boolean }>(`/workspaces/${workspaceId}/warned-users`);
  }

  async listProfileFlags(workspaceId: string) {
    return this.request<ProfileFlagEntry[]>(`/workspaces/${workspaceId}/profile-flags`);
  }

  async flagProfile(workspaceId: string, userId: string) {
    return this.request<{ success: boolean }>(`/workspaces/${workspaceId}/members/${userId}/profile-flag`, {
      method: 'PUT', body: JSON.stringify({}),
    });
  }

  async unflagProfile(workspaceId: string, userId: string) {
    return this.request<{ success: boolean }>(`/workspaces/${workspaceId}/members/${userId}/profile-flag`, { method: 'DELETE' });
  }

  async denyProfileAppeal(workspaceId: string, userId: string) {
    return this.request<{ success: boolean }>(`/workspaces/${workspaceId}/members/${userId}/profile-flag/deny`, {
      method: 'POST', body: JSON.stringify({}),
    });
  }

  async requestProfileAppeal(workspaceId: string) {
    return this.request<{ success: boolean }>(`/workspaces/${workspaceId}/profile-flag/appeal`, {
      method: 'POST', body: JSON.stringify({}),
    });
  }

  async getWorkspaceChannelState(workspaceId: string) {
    return this.request<ChannelReadState[]>(`/workspaces/${workspaceId}/channel-state`);
  }

  async getWorkspaceAuditLogs(workspaceId: string, cursor?: string, limit = 50) {
    const params = new URLSearchParams({ limit: String(limit) });
    if (cursor) params.set('cursor', cursor);
    return this.request<AuditLogPage>(`/workspaces/${workspaceId}/audit-logs?${params.toString()}`, { method: 'POST' });
  }

  async getWorkspaceAuditIntegrity(workspaceId: string) {
    return this.request<AuditIntegrityStatus>(`/workspaces/${workspaceId}/audit-integrity`, { method: 'POST' });
  }

  // Invitations
  async getInvitations(workspaceId: string) {
    return this.request<WorkspaceInvitation[]>(`/workspaces/${workspaceId}/invitations`);
  }

  async createInvitation(workspaceId: string, input: {
    email?: string;
    roleId?: string;
    expiresInSeconds: number;
  }) {
    return this.request<CreatedWorkspaceInvitation>(`/workspaces/${workspaceId}/invitations`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async revokeInvitation(workspaceId: string, invitationId: string) {
    return this.request<WorkspaceInvitation>(`/workspaces/${workspaceId}/invitations/${invitationId}`, {
      method: 'DELETE',
    });
  }

  async acceptInvitation(token: string) {
    return this.request<AcceptedInvitation>('/invitations/accept', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  // Roles and effective permissions
  async getRoles(workspaceId: string) {
    return this.request<WorkspaceRole[]>(`/workspaces/${workspaceId}/roles`);
  }

  async createRole(workspaceId: string, input: { name: string; permissions: number; position: number }) {
    return this.request<WorkspaceRole>(`/workspaces/${workspaceId}/roles`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateRole(workspaceId: string, roleId: string, input: {
    name?: string;
    permissions?: number;
    position?: number;
  }, authorizationRevision: string) {
    return this.request<RoleUpdateResult>(`/workspaces/${workspaceId}/roles/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(withExpectedAuthorizationRevision(input, authorizationRevision)),
    });
  }

  async deleteRole(workspaceId: string, roleId: string, authorizationRevision: string) {
    return this.request<{ roleId: string; workspaceId: string }>(`/workspaces/${workspaceId}/roles/${roleId}`, {
      method: 'DELETE',
      body: JSON.stringify(withExpectedAuthorizationRevision({}, authorizationRevision)),
    });
  }

  async previewRoleChange(workspaceId: string, input: RolePreviewInput) {
    return this.request<RoleChangePreview>(`/workspaces/${workspaceId}/roles/preview`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async assignRole(workspaceId: string, userId: string, roleId: string, authorizationRevision: string) {
    return this.request<RoleAssignmentResult>(`/workspaces/${workspaceId}/members/${userId}/roles/${roleId}`, {
      method: 'POST',
      body: JSON.stringify(withExpectedAuthorizationRevision({}, authorizationRevision)),
    });
  }

  async unassignRole(workspaceId: string, userId: string, roleId: string, authorizationRevision: string) {
    return this.request<RoleAssignmentResult>(`/workspaces/${workspaceId}/members/${userId}/roles/${roleId}`, {
      method: 'DELETE',
      body: JSON.stringify(withExpectedAuthorizationRevision({}, authorizationRevision)),
    });
  }

  async getMemberPermissions(workspaceId: string, userId: string) {
    return this.request<EffectivePermissions>(`/workspaces/${workspaceId}/members/${userId}/permissions`);
  }

  // Categories
  async getCategories(workspaceId: string) {
    return this.request<Category[]>(`/workspaces/${workspaceId}/categories`);
  }

  async createCategory(workspaceId: string, name: string, position?: number) {
    return this.request<Category>(`/workspaces/${workspaceId}/categories`, {
      method: 'POST',
      body: JSON.stringify({ name, ...(position === undefined ? {} : { position }) }),
    });
  }

  async updateCategory(workspaceId: string, categoryId: string, data: CategoryMutationInput) {
    return this.request<Category>(`/workspaces/${workspaceId}/categories/${categoryId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteCategory(workspaceId: string, categoryId: string) {
    return this.request<{ categoryId: string; workspaceId: string; movedChannelIds: string[] }>(
      `/workspaces/${workspaceId}/categories/${categoryId}`,
      { method: 'DELETE' },
    );
  }

  // Channels
  async getChannels(workspaceId: string) {
    return this.request<Channel[]>(`/workspaces/${workspaceId}/channels`);
  }

  async createChannel(workspaceId: string, name: string, options?: {
    categoryId?: string;
    type?: 'text' | 'announcement' | 'voice' | 'forum';
    isPrivate?: boolean;
    topic?: string;
    position?: number;
  }) {
    return this.request<Channel>(`/workspaces/${workspaceId}/channels`, {
      method: 'POST',
      body: JSON.stringify({ name, ...options }),
    });
  }

  async getChannel(id: string) {
    return this.request<Channel>(`/channels/${id}`);
  }

  async getChannelMembers(id: string) {
    return this.request<ChannelMemberSummary[]>(`/channels/${id}/members`);
  }

  async updateChannel(id: string, data: ChannelMutationInput) {
    return this.request<Channel>(`/channels/${id}`, { method: 'PUT', body: JSON.stringify(data) });
  }

  async updateChannelPreference(channelId: string, updates: {
    favorite?: boolean;
    muted?: boolean;
    hidden?: boolean;
    notificationLevel?: NotificationLevel;
  }) {
    return this.request<ChannelPreference>(`/channels/${channelId}/preferences`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async deleteChannel(id: string) {
    return this.request<SuccessResponse>(`/channels/${id}`, { method: 'DELETE' });
  }

  async addChannelMember(channelId: string, userId: string) {
    return this.request<{ channelId: string; userId: string }>(`/channels/${channelId}/members`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async removeChannelMember(channelId: string, userId: string) {
    return this.request<SuccessResponse>(`/channels/${channelId}/members/${userId}`, { method: 'DELETE' });
  }

  async getPermissionOverrides(target: PermissionOverrideTarget, workspaceId: string, targetId: string) {
    return this.request<PermissionOverride[]>(permissionOverridePath(target, workspaceId, targetId));
  }

  async previewPermissionOverride(
    target: PermissionOverrideTarget,
    workspaceId: string,
    targetId: string,
    input: PermissionOverridePreviewInput,
  ) {
    return this.request<PermissionOverridePreview>(`${permissionOverridePath(target, workspaceId, targetId)}/preview`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async upsertPermissionOverride(
    target: PermissionOverrideTarget,
    workspaceId: string,
    targetId: string,
    roleId: string,
    input: PermissionOverrideWriteInput,
  ) {
    return this.request<PermissionOverrideMutationResult>(`${permissionOverridePath(target, workspaceId, targetId)}/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  }

  async deletePermissionOverride(
    target: PermissionOverrideTarget,
    workspaceId: string,
    targetId: string,
    roleId: string,
    input: PermissionOverrideDeleteInput,
  ) {
    return this.request<PermissionOverrideDeleteResult>(`${permissionOverridePath(target, workspaceId, targetId)}/${roleId}`, {
      method: 'DELETE',
      body: JSON.stringify(input),
    });
  }

  async getEffectiveChannelPermissions(workspaceId: string, channelId: string, userId: string) {
    return this.request<ChannelEffectivePermissions>(
      `/workspaces/${workspaceId}/channels/${channelId}/permissions/effective?userId=${encodeURIComponent(userId)}`,
    );
  }

  async getDms(workspaceId: string) {
    return this.request<DirectMessageConversation[]>(`/workspaces/${workspaceId}/dms`);
  }

  async createDm(workspaceId: string, memberIds: string[]) {
    return this.request<DirectMessageConversation>(`/workspaces/${workspaceId}/dms`, {
      method: 'POST',
      body: JSON.stringify({ memberIds }),
    });
  }

  // Messages
  async getMessages(channelId: string, cursor?: string) {
    const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    return this.request<{ data: Message[]; hasMore: boolean; cursor: string | null }>(`/channels/${channelId}/messages${params}`);
  }

  async sendMessage(channelId: string, data: {
    encryptedContent: string;
    contentNonce: string;
    deviceId: string;
    keyVersion: number;
    idempotencyKey: string;
    signature: string;
    broadcastMention: boolean;
    mentionedUserIds?: string[];
    refMessageId?: string;
    postId?: string;
  }) {
    return this.request<Message>(`/channels/${channelId}/messages`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async editMessage(messageId: string, data: {
    encryptedContent: string;
    contentNonce: string;
    deviceId: string;
    keyVersion: number;
    idempotencyKey: string;
    signature: string;
    broadcastMention: boolean;
    postId?: string;
  }) {
    return this.request<Message>(`/messages/${messageId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteMessage(messageId: string, data: {
    deviceId: string;
    keyVersion: number;
    idempotencyKey: string;
    signature: string;
    postId?: string;
  }) {
    return this.request<{ messageId: string; channelId: string; event?: Message }>(`/messages/${messageId}`, { method: 'DELETE', body: JSON.stringify(data) });
  }

  // Forum
  async getForumPosts(channelId: string, options: { sort?: 'activity' | 'created'; tagId?: string; cursor?: string } = {}) {
    const params = new URLSearchParams();
    if (options.sort) params.set('sort', options.sort);
    if (options.tagId) params.set('tagId', options.tagId);
    if (options.cursor) params.set('cursor', options.cursor);
    const query = params.toString();
    return this.request<{ data: ForumPostSummary[]; hasMore: boolean; cursor: string | null; viewer: ForumViewerCapabilities }>(
      `/channels/${channelId}/forum/posts${query ? `?${query}` : ''}`,
    );
  }

  async createForumPost(channelId: string, data: {
    encryptedContent: string;
    contentNonce: string;
    deviceId: string;
    keyVersion: number;
    idempotencyKey: string;
    signature: string;
    broadcastMention: boolean;
    mentionedUserIds?: string[];
    tagIds?: string[];
  }) {
    return this.request<{ message: Message; state: Omit<ForumPostState, 'unread'> }>(`/channels/${channelId}/forum/posts`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getForumPost(postId: string) {
    return this.request<ForumPostSummary>(`/forum/posts/${postId}`);
  }

  async getForumPostMessages(postId: string, cursor?: string) {
    const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    return this.request<{ data: Message[]; hasMore: boolean; cursor: string | null }>(`/forum/posts/${postId}/messages${params}`);
  }

  /** `shownActivityAt`: the latest activity of the post that was shown to the viewer. */
  async markForumPostRead(postId: string, shownActivityAt: string) {
    return this.request<{ channelId: string; postId: string; lastReadActivityAt: string }>(`/forum/posts/${postId}/read`, {
      method: 'POST',
      body: JSON.stringify({ shownActivityAt }),
    });
  }

  async setForumPostLocked(postId: string, locked: boolean) {
    return this.request<Omit<ForumPostState, 'unread'>>(`/forum/posts/${postId}/lock`, {
      method: 'PUT',
      body: JSON.stringify({ locked }),
    });
  }

  async setForumPostResolved(postId: string, resolved: boolean) {
    return this.request<Omit<ForumPostState, 'unread'>>(`/forum/posts/${postId}/resolved`, {
      method: 'PUT',
      body: JSON.stringify({ resolved }),
    });
  }

  async setForumPostTags(postId: string, tagIds: string[]) {
    return this.request<Omit<ForumPostState, 'unread'>>(`/forum/posts/${postId}/tags`, {
      method: 'PUT',
      body: JSON.stringify({ tagIds }),
    });
  }

  async getForumTags(channelId: string) {
    return this.request<ForumTag[]>(`/channels/${channelId}/forum/tags`);
  }

  async createForumTag(channelId: string, name: string) {
    return this.request<ForumTag>(`/channels/${channelId}/forum/tags`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async updateForumTag(tagId: string, updates: { name?: string; position?: number }) {
    return this.request<ForumTag>(`/forum/tags/${tagId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async deleteForumTag(tagId: string) {
    return this.request<SuccessResponse>(`/forum/tags/${tagId}`, { method: 'DELETE' });
  }

  async toggleReaction(messageId: string, emoji: string) {
    return this.request<{
      messageId: string;
      channelId: string;
      userId: string;
      action: 'added' | 'removed';
      emoji: string;
      reactions: Reaction[];
    }>(`/messages/${messageId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
    });
  }

  async pinMessage(messageId: string) {
    return this.request<{ messageId: string; channelId: string; userId: string; pinned: boolean }>(`/messages/${messageId}/pin`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  /** Sets (rather than toggles) a forum post's pin, so repeating it is harmless. */
  async setForumPostPinned(postId: string, pinned: boolean) {
    return this.request<{
      messageId: string;
      channelId: string;
      userId: string;
      pinned: boolean;
      forumPost?: Omit<ForumPostState, 'unread'>;
    }>(`/messages/${postId}/pin`, {
      method: 'POST',
      body: JSON.stringify({ pinned }),
    });
  }

  async updateReadPosition(channelId: string, messageId: string) {
    return this.request<ReadPosition>(`/channels/${channelId}/read`, {
      method: 'POST',
      body: JSON.stringify({ messageId }),
    });
  }

  async toggleMessageBookmark(messageId: string) {
    return this.request<{
      messageId: string;
      channelId: string;
      bookmarked: boolean;
      createdAt: string | null;
    }>(`/messages/${messageId}/bookmark`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async getMessageBookmarks(limit = 100) {
    return this.request<MessageBookmark[]>(`/bookmarks?limit=${encodeURIComponent(String(limit))}`);
  }

  // E2EE attachments
  async createAttachmentUpload(input: AttachmentUploadCreateInput, signal?: AbortSignal) {
    return this.request<AttachmentUploadReservation>('/files/uploads', {
      method: 'POST',
      body: JSON.stringify(input),
      signal,
    });
  }

  async getAttachmentUploadStatus(uploadId: string, signal?: AbortSignal) {
    return this.request<AttachmentUploadStatus>(`/files/uploads/${uploadId}`, { signal });
  }

  async putAttachmentChunk(uploadId: string, index: number, ciphertext: ArrayBuffer, signal?: AbortSignal) {
    return this.request<AttachmentChunkUploadResult>(`/files/uploads/${uploadId}/chunks/${index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: ciphertext,
      signal,
    });
  }

  async finalizeAttachmentUpload(uploadId: string, input: AttachmentFinalizeInput, signal?: AbortSignal) {
    return this.request<Attachment>(`/files/uploads/${uploadId}/finalize`, {
      method: 'POST',
      body: JSON.stringify(input),
      signal,
    });
  }

  async cancelAttachmentUpload(uploadId: string, signal?: AbortSignal) {
    return this.request<AttachmentUploadCancellation>(`/files/uploads/${uploadId}`, {
      method: 'DELETE',
      signal,
    });
  }

  async getAttachmentMetadata(attachmentId: string, signal?: AbortSignal) {
    return this.request<Attachment>(`/files/${attachmentId}`, { signal });
  }

  async getAttachmentChunk(attachmentId: string, index: number, signal?: AbortSignal) {
    return this.requestArrayBuffer(`/files/${attachmentId}/chunks/${index}`, { signal });
  }

  // Devices
  async getDeviceChallenge() {
    return this.request<{ challenge: string }>('/devices/challenge', { method: 'POST' });
  }

  async registerDevice(
    name: string,
    identityKey: string,
    challenge: string,
    proof: string,
    currentPassword?: string,
  ) {
    return this.request<Device>('/devices', {
      method: 'POST',
      body: JSON.stringify({ name, identityKey, challenge, proof, currentPassword }),
    });
  }

  async getDevices() {
    return this.request<Device[]>('/devices');
  }

  async revokeDevice(id: string) {
    const device = (await this.getDevices()).find((d) => d.id === id);
    if (!device) throw new Error('DEVICE_NOT_FOUND');
    const decision = await (await import('./directory.service')).deviceDecision(device, 'revoke');
    return this.request<SuccessResponse>(`/devices/${id}`, { method: 'DELETE', body: JSON.stringify(decision) });
  }

  async bindDevice(id: string, challenge: string, proof: string) {
    return this.request<Device>(`/devices/${id}/bind`, {
      method: 'POST',
      body: JSON.stringify({ challenge, proof }),
    });
  }

  async getChannelKeys(channelId: string, version?: number | readonly number[], signal?: AbortSignal) {
    const query = version === undefined
      ? '?scope=current'
      : Array.isArray(version)
        ? `?versions=${encodeURIComponent(version.join(','))}`
        : `?version=${encodeURIComponent(String(version))}`;
    return this.request<ChannelKeyDelivery[]>(`/channels/${channelId}/keys${query}`, { signal });
  }

  async getKeyRecipients(channelId: string) {
    return this.request<ChannelKeyRecipientState>(`/channels/${channelId}/key-recipients`);
  }

  /**
   * `approved` (past messages and attachments) or `active` (key distributors
   * and call signaling); see deviceMeetsPolicy.
   */
  async getChannelDeviceDirectory(
    channelId: string,
    deviceIds: readonly string[],
    policy: 'approved' | 'active',
    signal?: AbortSignal,
  ) {
    const uniqueIds = [...new Set(deviceIds)];
    if (uniqueIds.length < 1 || uniqueIds.length > 64 || uniqueIds.length !== deviceIds.length) {
      throw new Error('Invalid bounded device-directory request');
    }
    const result = await this.request<Array<{ deviceId: string; userId: string; identityKey: string }>>(
      `/channels/${channelId}/device-directory?ids=${encodeURIComponent(uniqueIds.join(','))}`,
      { signal },
    );
    await (await import('./directory.service')).verifyDirectoryDevices(channelId, result, policy);
    return result;
  }

  async distributeChannelKeys(
    channelId: string,
    version: number,
    keyCommitment: string,
    keys: Array<{ deviceId: string; encryptedKey: string; signature: string }>,
  ) {
    return this.request(`/channels/${channelId}/keys`, {
      method: 'POST',
      body: JSON.stringify({ version, keyCommitment, keys }),
    });
  }

  async acknowledgeChannelKey(
    channelId: string,
    deliveryId: string,
    signature: string,
  ) {
    return this.request<{
      version: number;
      status: ChannelKeyEpochStatus;
      activated: boolean;
      confirmedAt: string;
    }>(`/channels/${channelId}/keys/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ deliveryId, signature }),
    });
  }

  async abortChannelKeyEpoch(
    channelId: string,
    version: number,
    keyCommitment: string,
    signature: string,
  ) {
    return this.request<{ version: number; status: 'aborted' }>(`/channels/${channelId}/keys/abort`, {
      method: 'POST',
      body: JSON.stringify({ version, keyCommitment, signature }),
    });
  }
}

export const api = new ApiService();

function permissionOverridePath(
  target: PermissionOverrideTarget,
  workspaceId: string,
  targetId: string,
): string {
  const collection = target === 'category' ? 'categories' : 'channels';
  return `/workspaces/${workspaceId}/${collection}/${targetId}/permission-overrides`;
}
