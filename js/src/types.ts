// src/types.ts — @quorum/sdk type definitions
export interface QuorumClientOptions {
  /** Base URL of the Quorum API, e.g. https://api.quorum.dev */
  baseURL: string;
  /** Your organisation's API key */
  apiKey: string;
}

export interface CreateRequestOptions {
  groupId: string;
  actionDescriptor: string;
  payloadHash: string;
  expiresIn?: number; // seconds, default 300
  metadata?: Record<string, unknown>;
}

export interface AuthorizeOptions {
  requestId: string;
  memberId: string;
  /** Argon2id-derived share hex. Use deriveShare() to produce this. */
  shareHex: string;
  /** Single-use member token from email/push link */
  token: string;
}

export type RequestStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'revoked';

export interface AuthRequest {
  id: string;
  groupId: string;
  actionDescriptor: string;
  payloadHash: string;
  status: RequestStatus;
  authorisationsReceived: number;
  thresholdRequired: number;
  expiresAt: string;
  createdAt: string;
}

export interface AuthorizeResult {
  status: RequestStatus;
  approved?: boolean;
  progress?: number;
  threshold?: number;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  createdAt: string;
}

export interface APIError {
  error: string;
  statusCode: number;
}
