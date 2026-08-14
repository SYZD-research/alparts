const API_BASE = '/api';

class ApiService {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Request failed' }));
      throw new Error(error.message || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Auth
  async register(email: string, password: string, displayName: string) {
    return this.request<any>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, displayName }),
    });
  }

  async login(email: string, password: string) {
    return this.request<any>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async logout() {
    return this.request<any>('/auth/logout', { method: 'POST' });
  }

  async getMe() {
    return this.request<any>('/auth/me');
  }

  // Workspaces
  async getWorkspaces() {
    return this.request<any[]>('/workspaces');
  }

  async createWorkspace(name: string) {
    return this.request<any>('/workspaces', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async getWorkspace(id: string) {
    return this.request<any>(`/workspaces/${id}`);
  }

  async getWorkspaceMembers(id: string) {
    return this.request<any[]>(`/workspaces/${id}/members`);
  }

  // Categories
  async getCategories(workspaceId: string) {
    return this.request<any[]>(`/workspaces/${workspaceId}/categories`);
  }

  async createCategory(workspaceId: string, name: string) {
    return this.request<any>(`/workspaces/${workspaceId}/categories`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  // Channels
  async getChannels(workspaceId: string) {
    return this.request<any[]>(`/workspaces/${workspaceId}/channels`);
  }

  async createChannel(workspaceId: string, name: string, options?: { categoryId?: string; isPrivate?: boolean; topic?: string }) {
    return this.request<any>(`/workspaces/${workspaceId}/channels`, {
      method: 'POST',
      body: JSON.stringify({ name, ...options }),
    });
  }

  async getChannel(id: string) {
    return this.request<any>(`/channels/${id}`);
  }

  async getChannelMembers(id: string) {
    return this.request<any[]>(`/channels/${id}/members`);
  }

  // Messages
  async getMessages(channelId: string, cursor?: string) {
    const params = cursor ? `?cursor=${cursor}` : '';
    return this.request<any>(`/channels/${channelId}/messages${params}`);
  }

  async sendMessage(channelId: string, data: {
    encryptedContent: string;
    contentNonce: string;
    idempotencyKey: string;
    refMessageId?: string;
  }) {
    return this.request<any>(`/channels/${channelId}/messages`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async editMessage(messageId: string, data: { encryptedContent: string; contentNonce: string }) {
    return this.request<any>(`/messages/${messageId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteMessage(messageId: string) {
    return this.request<any>(`/messages/${messageId}`, { method: 'DELETE' });
  }

  async toggleReaction(messageId: string, emoji: string) {
    return this.request<any>(`/messages/${messageId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
    });
  }

  async pinMessage(messageId: string, channelId: string) {
    return this.request<any>(`/messages/${messageId}/pin`, {
      method: 'POST',
      body: JSON.stringify({ channelId }),
    });
  }

  async updateReadPosition(channelId: string, messageId: string) {
    return this.request<any>(`/channels/${channelId}/read`, {
      method: 'POST',
      body: JSON.stringify({ messageId }),
    });
  }

  // Devices
  async registerDevice(name: string, identityKey: string) {
    return this.request<any>('/devices', {
      method: 'POST',
      body: JSON.stringify({ name, identityKey }),
    });
  }

  async getDevices() {
    return this.request<any[]>('/devices');
  }

  async revokeDevice(id: string) {
    return this.request<any>(`/devices/${id}`, { method: 'DELETE' });
  }
}

export const api = new ApiService();
