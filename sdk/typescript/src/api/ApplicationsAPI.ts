/**
 * Applications API service
 */

import {BaseAPI} from './BaseAPI';
import type {
    Application,
    CreateApplicationData,
    ListOptions,
    PaginatedResponse,
    UpdateApplicationData,
} from '../types';

export class ApplicationsAPI extends BaseAPI {
  /**
   * List applications
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<Application>> {
    return this.get<PaginatedResponse<Application>>('/v1/applications', {
      params: options,
    });
  }

  /**
   * Get application by ID
   */
  async get(id: string): Promise<Application> {
    return this.get<Application>(`/v1/applications/${id}`);
  }

  /**
   * Create a new application
   */
  async create(data: CreateApplicationData): Promise<Application> {
    return this.post<Application>('/v1/applications', data);
  }

  /**
   * Update application
   */
  async update(id: string, data: UpdateApplicationData): Promise<Application> {
    return this.put<Application>(`/v1/applications/${id}`, data);
  }

  /**
   * Delete application
   */
  async delete(id: string): Promise<void> {
    return this.delete<void>(`/v1/applications/${id}`);
  }

  /**
   * Regenerate application credentials
   */
  async regenerateCredentials(id: string): Promise<{
    client_id: string;
    client_secret: string;
  }> {
    return this.post<{ client_id: string; client_secret: string }>(
      `/v1/applications/${id}/credentials/regenerate`
    );
  }

  /**
   * Get application users
   */
  async getUsers(id: string, options?: ListOptions): Promise<any[]> {
    return this.get<any[]>(`/v1/applications/${id}/users`, { params: options });
  }

  /**
   * Grant user access to application
   */
  async grantUserAccess(applicationId: string, userId: string): Promise<void> {
    return this.post<void>(`/v1/applications/${applicationId}/users`, {
      user_id: userId,
    });
  }

  /**
   * Revoke user access to application
   */
  async revokeUserAccess(applicationId: string, userId: string): Promise<void> {
    return this.delete<void>(`/v1/applications/${applicationId}/users/${userId}`);
  }

  /**
   * Get application tokens
   */
  async getTokens(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/applications/${id}/tokens`);
  }

  /**
   * Revoke all application tokens
   */
  async revokeAllTokens(id: string): Promise<void> {
    return this.delete<void>(`/v1/applications/${id}/tokens`);
  }

  /**
   * Revoke specific application token
   */
  async revokeToken(applicationId: string, tokenId: string): Promise<void> {
    return this.delete<void>(`/v1/applications/${applicationId}/tokens/${tokenId}`);
  }

  /**
   * Get application analytics
   */
  async getAnalytics(id: string, params?: any): Promise<any> {
    return this.get<any>(`/v1/applications/${id}/analytics`, { params });
  }
}
