/**
 * Main AuthOS Client
 */

import type {AuthOSConfig, LoginCredentials, RegisterData, User} from './types';
import {AuthService} from './auth/AuthService';
import {TokenManager} from './auth/TokenManager';
import {UsersAPI} from './api/UsersAPI';
import {OrganizationsAPI} from './api/OrganizationsAPI';
import {ApplicationsAPI} from './api/ApplicationsAPI';
import {getDefaultStorage} from './utils/storage';
import {ConfigurationError} from './errors';

export class AuthOSClient {
  private config: AuthOSConfig;
  private tokenManager: TokenManager;
  private authService: AuthService;

  // API services
  public readonly users: UsersAPI;
  public readonly organizations: OrganizationsAPI;
  public readonly applications: ApplicationsAPI;

  constructor(config: AuthOSConfig) {
    this.validateConfig(config);
    this.config = this.normalizeConfig(config);

    // Initialize token manager
    this.tokenManager = new TokenManager(
      this.config.storage || getDefaultStorage()
    );

    // Initialize auth service
    this.authService = new AuthService(this.config, this.tokenManager);

    // Initialize API services
    this.users = new UsersAPI(this.config, this.tokenManager);
    this.organizations = new OrganizationsAPI(this.config, this.tokenManager);
    this.applications = new ApplicationsAPI(this.config, this.tokenManager);
  }

  /**
   * Validate configuration
   */
  private validateConfig(config: AuthOSConfig): void {
    if (!config.baseUrl) {
      throw new ConfigurationError('baseUrl is required');
    }

    if (!config.clientId) {
      throw new ConfigurationError('clientId is required');
    }

    // Validate URL format
    try {
      new URL(config.baseUrl);
    } catch {
      throw new ConfigurationError('baseUrl must be a valid URL');
    }
  }

  /**
   * Normalize configuration
   */
  private normalizeConfig(config: AuthOSConfig): AuthOSConfig {
    return {
      ...config,
      baseUrl: config.baseUrl.replace(/\/$/, ''), // Remove trailing slash
      scopes: config.scopes || ['openid', 'profile', 'email'],
      usePKCE: config.usePKCE !== false,
      autoRefresh: config.autoRefresh !== false,
      timeout: config.timeout || 30000,
    };
  }

  /**
   * Authentication methods
   */
  get auth() {
    return {
      /**
       * Login with email and password
       */
      login: async (credentials: LoginCredentials) => {
        return await this.authService.login(credentials);
      },

      /**
       * Register a new user
       */
      register: async (data: RegisterData) => {
        return await this.authService.register(data);
      },

      /**
       * Initiate OAuth flow (returns authorization URL)
       */
      initiateOAuthFlow: async () => {
        const url = await this.authService.initiateOAuthFlow();
        if (typeof window !== 'undefined') {
          window.location.href = url;
        }
        return url;
      },

      /**
       * Handle OAuth callback
       */
      handleCallback: async (callbackUrl?: string) => {
        const url = callbackUrl || (typeof window !== 'undefined' ? window.location.href : '');
        if (!url) {
          throw new ConfigurationError('Callback URL is required');
        }
        return await this.authService.handleOAuthCallback(url);
      },

      /**
       * Get current user
       */
      getUser: async (): Promise<User> => {
        return await this.authService.getUser();
      },

      /**
       * Logout
       */
      logout: async () => {
        return await this.authService.logout();
      },

      /**
       * Check if authenticated
       */
      isAuthenticated: async (): Promise<boolean> => {
        return await this.authService.isAuthenticated();
      },

      /**
       * Refresh access token
       */
      refreshToken: async () => {
        return await this.authService.refreshToken();
      },

      /**
       * Get token manager (for advanced usage)
       */
      getTokenManager: () => {
        return this.tokenManager;
      },
    };
  }

  /**
   * Get configuration
   */
  getConfig(): Readonly<AuthOSConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<AuthOSConfig>): void {
    this.config = { ...this.config, ...updates };
  }
}
