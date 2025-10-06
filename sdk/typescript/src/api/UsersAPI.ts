/**
 * Users API service
 */

import {BaseAPI} from './BaseAPI';
import type {CreateUserData, ListOptions, PaginatedResponse, UpdateUserData, User,} from '../types';

export class UsersAPI extends BaseAPI {
  /**
   * List users
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<User>> {
    return this.get<PaginatedResponse<User>>('/v1/users', { params: options });
  }

  /**
   * Get user by ID
   */
  async get(id: string): Promise<User> {
    return this.get<User>(`/v1/users/${id}`);
  }

  /**
   * Create a new user
   */
  async create(data: CreateUserData): Promise<User> {
    return this.post<User>('/v1/users', data);
  }

  /**
   * Update user
   */
  async update(id: string, data: UpdateUserData): Promise<User> {
    return this.put<User>(`/v1/users/${id}`, data);
  }

  /**
   * Delete user
   */
  async delete(id: string): Promise<void> {
    return this.delete<void>(`/v1/users/${id}`);
  }

  /**
   * Get user's applications
   */
  async getApplications(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/users/${id}/applications`);
  }

  /**
   * Grant user access to application
   */
  async grantApplicationAccess(userId: string, applicationId: string): Promise<void> {
    return this.post<void>(`/v1/users/${userId}/applications`, {
      application_id: applicationId,
    });
  }

  /**
   * Revoke user access to application
   */
  async revokeApplicationAccess(userId: string, applicationId: string): Promise<void> {
    return this.delete<void>(`/v1/users/${userId}/applications/${applicationId}`);
  }

  /**
   * Get user's roles
   */
  async getRoles(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/users/${id}/roles`);
  }

  /**
   * Assign role to user
   */
  async assignRole(userId: string, roleId: string): Promise<void> {
    return this.post<void>(`/v1/users/${userId}/roles`, { role_id: roleId });
  }

  /**
   * Remove role from user
   */
  async removeRole(userId: string, roleId: string): Promise<void> {
    return this.delete<void>(`/v1/users/${userId}/roles/${roleId}`);
  }

  /**
   * Get user's sessions
   */
  async getSessions(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/users/${id}/sessions`);
  }

  /**
   * Revoke all user sessions
   */
  async revokeSessions(id: string): Promise<void> {
    return this.delete<void>(`/v1/users/${id}/sessions`);
  }

  /**
   * Revoke specific user session
   */
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    return this.delete<void>(`/v1/users/${userId}/sessions/${sessionId}`);
  }

  /**
   * Bulk update users
   */
  async bulkUpdate(updates: Array<{ id: string; data: UpdateUserData }>): Promise<void> {
    return this.patch<void>('/v1/users/bulk', { updates });
  }
}
