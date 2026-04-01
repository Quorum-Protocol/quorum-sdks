// src/client.ts — QuorumClient: full REST API wrapper
import type {
  QuorumClientOptions, CreateRequestOptions, AuthorizeOptions,
  AuthRequest, AuthorizeResult, Webhook, APIError,
} from './types';

export class QuorumClient {
  private readonly baseURL: string;
  private readonly headers: Record<string, string>;

  constructor(options: QuorumClientOptions) {
    this.baseURL = options.baseURL.replace(/\/$/, '');
    this.headers = {
      'Authorization': `Bearer ${options.apiKey}`,
      'Content-Type': 'application/json',
    };
  }

  // ── Requests ──────────────────────────────────────────────────────────────

  async createRequest(opts: CreateRequestOptions): Promise<AuthRequest> {
    return this.post<AuthRequest>('/v1/requests', {
      group_id:          opts.groupId,
      action_descriptor: opts.actionDescriptor,
      payload_hash:      opts.payloadHash,
      expires_in:        opts.expiresIn ?? 300,
      metadata:          opts.metadata,
    });
  }

  async getRequest(requestId: string): Promise<AuthRequest> {
    return this.get<AuthRequest>(`/v1/requests/${requestId}`);
  }

  async revokeRequest(requestId: string): Promise<void> {
    await this.delete(`/v1/requests/${requestId}`);
  }

  // ── Authorisation ─────────────────────────────────────────────────────────

  async authorize(opts: AuthorizeOptions): Promise<AuthorizeResult> {
    return this.post<AuthorizeResult>('/v1/authorize', {
      request_id: opts.requestId,
      member_id:  opts.memberId,
      share_hex:  opts.shareHex,
      token:      opts.token,
    });
  }

  // ── Webhooks ──────────────────────────────────────────────────────────────

  async createWebhook(url: string, events: string[], secret: string): Promise<Webhook> {
    return this.post<Webhook>('/v1/webhooks', { url, events, secret });
  }

  async listWebhooks(): Promise<Webhook[]> {
    return this.get<Webhook[]>('/v1/webhooks');
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.delete(`/v1/webhooks/${webhookId}`);
  }

  // ── Groups ────────────────────────────────────────────────────────────────

  async getGroup(groupId: string): Promise<unknown> {
    return this.get(`/v1/groups/${groupId}`);
  }

  // ── API Keys ──────────────────────────────────────────────────────────────

  /** Creates an API key. The raw key is returned ONCE — store it securely. */
  async createAPIKey(name: string): Promise<{ id: string; key: string; prefix: string }> {
    return this.post('/v1/api-keys', { name });
  }

  async listAPIKeys(): Promise<Array<{ id: string; name: string; prefix: string }>> {
    return this.get('/v1/api-keys');
  }

  async revokeAPIKey(keyId: string): Promise<void> {
    await this.delete(`/v1/api-keys/${keyId}`);
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  async getAuditLog(params?: {
    requestId?: string;
    groupId?:   string;
    eventType?: string;
    since?:     string;
    until?:     string;
    limit?:     number;
    cursor?:    string;
  }): Promise<unknown> {
    const qs = new URLSearchParams();
    if (params?.requestId) qs.set('request_id', params.requestId);
    if (params?.groupId)   qs.set('group_id',   params.groupId);
    if (params?.eventType) qs.set('event_type', params.eventType);
    if (params?.since)     qs.set('since',      params.since);
    if (params?.until)     qs.set('until',      params.until);
    if (params?.limit)     qs.set('limit',      String(params.limit));
    if (params?.cursor)    qs.set('cursor',     params.cursor);
    const query = qs.toString() ? `?${qs.toString()}` : '';
    return this.get(`/v1/audit${query}`);
  }

  // ── Internal HTTP helpers ─────────────────────────────────────────────────

  private async get<T>(path: string): Promise<T> {
    const resp = await fetch(`${this.baseURL}${path}`, { headers: this.headers });
    return this.parseResponse<T>(resp);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(`${this.baseURL}${path}`, {
      method:  'POST',
      headers: this.headers,
      body:    JSON.stringify(body),
    });
    return this.parseResponse<T>(resp);
  }

  private async delete(path: string): Promise<void> {
    const resp = await fetch(`${this.baseURL}${path}`, {
      method:  'DELETE',
      headers: this.headers,
    });
    if (resp.status === 204) return;
    await this.parseResponse(resp);
  }

  private async parseResponse<T>(resp: Response): Promise<T> {
    let data: unknown;
    const contentType = resp.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      data = await resp.json();
    } else {
      data = await resp.text();
    }
    if (!resp.ok) {
      const err = data as APIError;
      throw Object.assign(new Error(err?.error ?? `HTTP ${resp.status}`), {
        statusCode: resp.status,
      });
    }
    return data as T;
  }
}
