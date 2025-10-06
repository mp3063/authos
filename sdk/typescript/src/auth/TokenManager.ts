/**
 * Token manager with automatic refresh
 */

import type {Storage, TokenInfo, TokenResponse} from '../types';
import {RefreshTokenError} from '../errors';
import {MemoryStorage} from '../utils/storage';

const TOKEN_KEY = 'access_token';
const REFRESH_KEY = 'refresh_token';
const EXPIRES_AT_KEY = 'expires_at';

export class TokenManager {
  private storage: Storage;
  private refreshPromise: Promise<TokenInfo> | null = null;
  private refreshCallback?: () => Promise<TokenResponse>;

  constructor(
    storage?: Storage,
    refreshCallback?: () => Promise<TokenResponse>
  ) {
    this.storage = storage || new MemoryStorage();
    this.refreshCallback = refreshCallback;
  }

  /**
   * Set refresh callback for automatic token refresh
   */
  setRefreshCallback(callback: () => Promise<TokenResponse>): void {
    this.refreshCallback = callback;
  }

  /**
   * Store tokens
   */
  async setTokens(tokenResponse: TokenResponse): Promise<void> {
    const expiresAt = Date.now() + tokenResponse.expires_in * 1000;

    await Promise.all([
      this.storage.setItem(TOKEN_KEY, tokenResponse.access_token),
      this.storage.setItem(EXPIRES_AT_KEY, expiresAt.toString()),
      tokenResponse.refresh_token
        ? this.storage.setItem(REFRESH_KEY, tokenResponse.refresh_token)
        : Promise.resolve(),
    ]);
  }

  /**
   * Get access token (with automatic refresh if expired)
   */
  async getAccessToken(): Promise<string | null> {
    const token = await this.storage.getItem(TOKEN_KEY);

    if (!token) {
      return null;
    }

    // Check if token is expired
    if (await this.isExpired()) {
      // Try to refresh
      const refreshed = await this.refreshIfNeeded();
      return refreshed ? refreshed.access_token : null;
    }

    return token;
  }

  /**
   * Get refresh token
   */
  async getRefreshToken(): Promise<string | null> {
    return await this.storage.getItem(REFRESH_KEY);
  }

  /**
   * Get token info
   */
  async getTokenInfo(): Promise<TokenInfo | null> {
    const [accessToken, refreshToken, expiresAt] = await Promise.all([
      this.storage.getItem(TOKEN_KEY),
      this.storage.getItem(REFRESH_KEY),
      this.storage.getItem(EXPIRES_AT_KEY),
    ]);

    if (!accessToken || !expiresAt) {
      return null;
    }

    const expiresAtNum = parseInt(expiresAt, 10);
    const expiresIn = Math.max(0, Math.floor((expiresAtNum - Date.now()) / 1000));

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      expires_at: expiresAtNum,
      refresh_token: refreshToken || undefined,
    };
  }

  /**
   * Check if token is expired
   */
  async isExpired(): Promise<boolean> {
    const expiresAt = await this.storage.getItem(EXPIRES_AT_KEY);

    if (!expiresAt) {
      return true;
    }

    const expiresAtNum = parseInt(expiresAt, 10);
    // Add 60 second buffer
    return Date.now() >= expiresAtNum - 60000;
  }

  /**
   * Refresh token if needed (with single-promise pattern to prevent race conditions)
   */
  async refreshIfNeeded(): Promise<TokenInfo | null> {
    // If already refreshing, return existing promise
    if (this.refreshPromise) {
      return await this.refreshPromise;
    }

    // Check if token needs refresh
    if (!(await this.isExpired())) {
      return await this.getTokenInfo();
    }

    // Check if refresh token exists
    const refreshToken = await this.getRefreshToken();
    if (!refreshToken) {
      throw new RefreshTokenError('No refresh token available');
    }

    // Check if refresh callback is set
    if (!this.refreshCallback) {
      throw new RefreshTokenError('No refresh callback configured');
    }

    // Create refresh promise
    this.refreshPromise = this.performRefresh();

    try {
      const result = await this.refreshPromise;
      return result;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Perform the actual token refresh
   */
  private async performRefresh(): Promise<TokenInfo> {
    if (!this.refreshCallback) {
      throw new RefreshTokenError('No refresh callback configured');
    }

    try {
      const tokenResponse = await this.refreshCallback();
      await this.setTokens(tokenResponse);
      const tokenInfo = await this.getTokenInfo();

      if (!tokenInfo) {
        throw new RefreshTokenError('Failed to retrieve token info after refresh');
      }

      return tokenInfo;
    } catch (error) {
      // Clear tokens on refresh failure
      await this.clearTokens();
      throw new RefreshTokenError(
        error instanceof Error ? error.message : 'Token refresh failed'
      );
    }
  }

  /**
   * Clear all tokens
   */
  async clearTokens(): Promise<void> {
    await Promise.all([
      this.storage.removeItem(TOKEN_KEY),
      this.storage.removeItem(REFRESH_KEY),
      this.storage.removeItem(EXPIRES_AT_KEY),
    ]);
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    const token = await this.storage.getItem(TOKEN_KEY);
    return !!token;
  }
}
