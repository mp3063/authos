/**
 * Authentication service with OAuth 2.0 + PKCE support
 */

import type {AuthOSConfig, LoginCredentials, OAuthState, RegisterData, TokenResponse, User,} from '../types';
import {TokenManager} from './TokenManager';
import {generatePKCEChallenge, generatePlainPKCEChallenge, generateState} from '../utils/pkce';
import {AuthenticationError, ConfigurationError} from '../errors';

export class AuthService {
  private config: AuthOSConfig;
  private tokenManager: TokenManager;
  private fetchFn: typeof fetch;

  constructor(config: AuthOSConfig, tokenManager: TokenManager) {
    this.config = config;
    this.tokenManager = tokenManager;
    this.fetchFn = config.fetch || fetch;

    // Set refresh callback
    this.tokenManager.setRefreshCallback(() => this.refreshToken());
  }

  /**
   * Login with email and password
   */
  async login(credentials: LoginCredentials): Promise<TokenResponse> {
    const response = await this.fetchFn(`${this.config.baseUrl}/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthenticationError(
        error.message || 'Login failed',
        {
          url: response.url,
          method: 'POST',
          status: response.status,
          statusText: response.statusText,
        }
      );
    }

    const data = await response.json();
    const tokenResponse: TokenResponse = data.data;

    await this.tokenManager.setTokens(tokenResponse);

    return tokenResponse;
  }

  /**
   * Register a new user
   */
  async register(registerData: RegisterData): Promise<TokenResponse> {
    const response = await this.fetchFn(`${this.config.baseUrl}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(registerData),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthenticationError(
        error.message || 'Registration failed',
        {
          url: response.url,
          method: 'POST',
          status: response.status,
          statusText: response.statusText,
        }
      );
    }

    const data = await response.json();
    const tokenResponse: TokenResponse = data.data;

    await this.tokenManager.setTokens(tokenResponse);

    return tokenResponse;
  }

  /**
   * Initiate OAuth 2.0 authorization code flow with PKCE
   */
  async initiateOAuthFlow(): Promise<string> {
    if (!this.config.redirectUri) {
      throw new ConfigurationError('redirectUri is required for OAuth flow');
    }

    const state = generateState();
    const scopes = this.config.scopes || ['openid', 'profile', 'email'];

    // Generate PKCE challenge
    const pkce = this.config.usePKCE !== false
      ? await generatePKCEChallenge().catch(() => generatePlainPKCEChallenge())
      : null;

    // Store OAuth state
    const oauthState: OAuthState = {
      state,
      code_verifier: pkce?.code_verifier,
      redirect_uri: this.config.redirectUri,
      scope: scopes,
    };

    // Store state in session/local storage
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem('authos_oauth_state', JSON.stringify(oauthState));
    }

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
    });

    if (pkce) {
      params.append('code_challenge', pkce.code_challenge);
      params.append('code_challenge_method', pkce.code_challenge_method);
    }

    return `${this.config.baseUrl}/oauth/authorize?${params.toString()}`;
  }

  /**
   * Handle OAuth callback
   */
  async handleOAuthCallback(callbackUrl: string): Promise<TokenResponse> {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');

    if (error) {
      throw new AuthenticationError(`OAuth error: ${error}`);
    }

    if (!code || !state) {
      throw new AuthenticationError('Missing code or state parameter');
    }

    // Retrieve and validate state
    let oauthState: OAuthState | null = null;
    if (typeof sessionStorage !== 'undefined') {
      const storedState = sessionStorage.getItem('authos_oauth_state');
      if (storedState) {
        oauthState = JSON.parse(storedState);
        sessionStorage.removeItem('authos_oauth_state');
      }
    }

    if (!oauthState || oauthState.state !== state) {
      throw new AuthenticationError('Invalid state parameter');
    }

    // Exchange code for tokens
    return await this.exchangeCodeForToken(code, oauthState);
  }

  /**
   * Exchange authorization code for access token
   */
  private async exchangeCodeForToken(code: string, oauthState: OAuthState): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      code,
      redirect_uri: oauthState.redirect_uri,
    };

    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret;
    }

    if (oauthState.code_verifier) {
      body.code_verifier = oauthState.code_verifier;
    }

    const response = await this.fetchFn(`${this.config.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(body).toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthenticationError(
        error.error_description || error.message || 'Token exchange failed',
        {
          url: response.url,
          method: 'POST',
          status: response.status,
          statusText: response.statusText,
        }
      );
    }

    const tokenResponse: TokenResponse = await response.json();
    await this.tokenManager.setTokens(tokenResponse);

    return tokenResponse;
  }

  /**
   * Refresh access token
   */
  async refreshToken(): Promise<TokenResponse> {
    const refreshToken = await this.tokenManager.getRefreshToken();

    if (!refreshToken) {
      throw new AuthenticationError('No refresh token available');
    }

    const body: Record<string, string> = {
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    };

    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret;
    }

    const response = await this.fetchFn(`${this.config.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(body).toString(),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthenticationError(
        error.error_description || error.message || 'Token refresh failed',
        {
          url: response.url,
          method: 'POST',
          status: response.status,
          statusText: response.statusText,
        }
      );
    }

    const tokenResponse: TokenResponse = await response.json();
    await this.tokenManager.setTokens(tokenResponse);

    return tokenResponse;
  }

  /**
   * Get current authenticated user
   */
  async getUser(): Promise<User> {
    const token = await this.tokenManager.getAccessToken();

    if (!token) {
      throw new AuthenticationError('Not authenticated');
    }

    const response = await this.fetchFn(`${this.config.baseUrl}/v1/auth/user`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new AuthenticationError('Failed to get user', {
        url: response.url,
        method: 'GET',
        status: response.status,
        statusText: response.statusText,
      });
    }

    const data = await response.json();
    return data.data;
  }

  /**
   * Logout
   */
  async logout(): Promise<void> {
    const token = await this.tokenManager.getAccessToken();

    if (token) {
      try {
        await this.fetchFn(`${this.config.baseUrl}/v1/auth/logout`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } catch (error) {
        // Ignore errors during logout
      }
    }

    await this.tokenManager.clearTokens();
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    return await this.tokenManager.isAuthenticated();
  }

  /**
   * Get token manager
   */
  getTokenManager(): TokenManager {
    return this.tokenManager;
  }
}
