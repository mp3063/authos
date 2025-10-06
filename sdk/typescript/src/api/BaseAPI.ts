/**
 * Base API client with automatic auth and error handling
 */

import type {ApiResponse, AuthOSConfig, RequestOptions} from '../types';
import {TokenManager} from '../auth/TokenManager';
import {
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
} from '../errors';

export class BaseAPI {
  protected config: AuthOSConfig;
  protected tokenManager: TokenManager;
  protected fetchFn: typeof fetch;

  constructor(config: AuthOSConfig, tokenManager: TokenManager) {
    this.config = config;
    this.tokenManager = tokenManager;
    this.fetchFn = config.fetch || fetch;
  }

  /**
   * Make authenticated HTTP request
   */
  protected async request<T = any>(
    endpoint: string,
    options: RequestInit & RequestOptions = {}
  ): Promise<T> {
    const url = this.buildUrl(endpoint, options.params);
    const headers = await this.buildHeaders(options);

    const timeout = options.timeout || this.config.timeout || 30000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await this.fetchFn(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      return await this.handleResponse<T>(response, url, options.method || 'GET');
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        throw new NetworkError(`Request timeout after ${timeout}ms`, {
          url,
          method: options.method || 'GET',
        });
      }

      throw error;
    }
  }

  /**
   * Build full URL with query parameters
   */
  private buildUrl(endpoint: string, params?: Record<string, any>): string {
    const base = `${this.config.baseUrl}${endpoint}`;

    if (!params) {
      return base;
    }

    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, String(value));
      }
    });

    const query = searchParams.toString();
    return query ? `${base}?${query}` : base;
  }

  /**
   * Build request headers
   */
  private async buildHeaders(options: RequestOptions = {}): Promise<Headers> {
    const headers = new Headers(options.headers || {});

    // Set content type if not present
    if (!headers.has('Content-Type') && options.method !== 'GET') {
      headers.set('Content-Type', 'application/json');
    }

    // Add authorization header
    if (!options.skipAuth) {
      const token = await this.tokenManager.getAccessToken();
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
    }

    // Add user agent
    headers.set('User-Agent', 'AuthOS-SDK-TypeScript/1.0.0');

    return headers;
  }

  /**
   * Handle HTTP response
   */
  private async handleResponse<T>(
    response: Response,
    url: string,
    method: string
  ): Promise<T> {
    const context = {
      url,
      method,
      status: response.status,
      statusText: response.statusText,
    };

    // Success responses
    if (response.ok) {
      // 204 No Content
      if (response.status === 204) {
        return undefined as T;
      }

      const data: ApiResponse<T> = await response.json();
      return data.data as T;
    }

    // Error responses
    const errorData = await response.json().catch(() => ({
      message: response.statusText,
    }));

    switch (response.status) {
      case 401:
        throw new AuthenticationError(
          errorData.message || 'Authentication required',
          context
        );

      case 403:
        throw new AuthorizationError(
          errorData.message || 'Permission denied',
          context
        );

      case 404:
        throw new NotFoundError(
          errorData.message || 'Resource not found',
          context
        );

      case 422:
        throw new ValidationError(
          errorData.message || 'Validation failed',
          errorData.errors,
          context
        );

      case 429:
        const retryAfter = response.headers.get('Retry-After');
        throw new RateLimitError(
          errorData.message || 'Rate limit exceeded',
          retryAfter ? parseInt(retryAfter, 10) : undefined,
          context
        );

      case 500:
      case 502:
      case 503:
      case 504:
        throw new ServerError(
          errorData.message || 'Server error',
          context
        );

      default:
        throw new NetworkError(
          errorData.message || `HTTP ${response.status}`,
          context
        );
    }
  }

  /**
   * GET request
   */
  protected async get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' });
  }

  /**
   * POST request
   */
  protected async post<T>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  /**
   * PUT request
   */
  protected async put<T>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  /**
   * PATCH request
   */
  protected async patch<T>(
    endpoint: string,
    body?: any,
    options?: RequestOptions
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  /**
   * DELETE request
   */
  protected async delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' });
  }
}
