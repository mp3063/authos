/**
 * Core type definitions for AuthOS SDK
 */

export interface AuthOSConfig {
  /** Base URL of the AuthOS server */
  baseUrl: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret (optional, for server-side) */
  clientSecret?: string;
  /** Redirect URI for OAuth flow */
  redirectUri?: string;
  /** OAuth scopes to request */
  scopes?: string[];
  /** Custom storage implementation */
  storage?: Storage;
  /** Enable PKCE (default: true) */
  usePKCE?: boolean;
  /** Custom fetch implementation */
  fetch?: typeof fetch;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Enable automatic token refresh */
  autoRefresh?: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface TokenInfo extends TokenResponse {
  expires_at: number;
}

export interface User {
  id: string;
  name: string;
  email: string;
  email_verified_at: string | null;
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
  organization_id?: string;
  avatar_url?: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  settings: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Application {
  id: string;
  name: string;
  client_id: string;
  redirect_uris: string[];
  created_at: string;
  updated_at: string;
  organization_id: string;
}

export interface AuthenticationLog {
  id: string;
  user_id: string;
  ip_address: string;
  user_agent: string;
  login_at: string;
  logout_at: string | null;
  login_successful: boolean;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  errors?: Record<string, string[]>;
}

export interface PaginatedResponse<T = any> {
  success: boolean;
  data: T[];
  meta: {
    current_page: number;
    from: number;
    last_page: number;
    per_page: number;
    to: number;
    total: number;
  };
  links: {
    first: string;
    last: string;
    prev: string | null;
    next: string | null;
  };
}

export interface ListOptions {
  page?: number;
  per_page?: number;
  sort?: string;
  filter?: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  name: string;
  email: string;
  password: string;
  organization_id?: string;
}

export interface CreateUserData {
  name: string;
  email: string;
  password: string;
  organization_id?: string;
}

export interface UpdateUserData {
  name?: string;
  email?: string;
}

export interface CreateOrganizationData {
  name: string;
  slug?: string;
  settings?: Record<string, any>;
}

export interface UpdateOrganizationData {
  name?: string;
  settings?: Record<string, any>;
}

export interface CreateApplicationData {
  name: string;
  redirect_uris: string[];
  organization_id?: string;
}

export interface UpdateApplicationData {
  name?: string;
  redirect_uris?: string[];
}

export interface MFASetupResponse {
  secret: string;
  qr_code: string;
  recovery_codes: string[];
}

export interface SocialProvider {
  name: string;
  enabled: boolean;
  authorization_url: string;
}

export interface PKCEChallenge {
  code_verifier: string;
  code_challenge: string;
  code_challenge_method: 'S256' | 'plain';
}

export interface OAuthState {
  state: string;
  code_verifier?: string;
  redirect_uri: string;
  scope: string[];
}

export interface Storage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, any>;
  timeout?: number;
  skipAuth?: boolean;
}

export interface ErrorContext {
  url: string;
  method: string;
  status?: number;
  statusText?: string;
}
