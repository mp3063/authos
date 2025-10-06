/**
 * Organizations API service
 */

import {BaseAPI} from './BaseAPI';
import type {
    CreateOrganizationData,
    ListOptions,
    Organization,
    PaginatedResponse,
    UpdateOrganizationData,
} from '../types';

export class OrganizationsAPI extends BaseAPI {
  /**
   * List organizations
   */
  async list(options?: ListOptions): Promise<PaginatedResponse<Organization>> {
    return this.get<PaginatedResponse<Organization>>('/v1/organizations', {
      params: options,
    });
  }

  /**
   * Get organization by ID
   */
  async get(id: string): Promise<Organization> {
    return this.get<Organization>(`/v1/organizations/${id}`);
  }

  /**
   * Create a new organization
   */
  async create(data: CreateOrganizationData): Promise<Organization> {
    return this.post<Organization>('/v1/organizations', data);
  }

  /**
   * Update organization
   */
  async update(id: string, data: UpdateOrganizationData): Promise<Organization> {
    return this.put<Organization>(`/v1/organizations/${id}`, data);
  }

  /**
   * Delete organization
   */
  async delete(id: string): Promise<void> {
    return this.delete<void>(`/v1/organizations/${id}`);
  }

  /**
   * Get organization settings
   */
  async getSettings(id: string): Promise<Record<string, any>> {
    return this.get<Record<string, any>>(`/v1/organizations/${id}/settings`);
  }

  /**
   * Update organization settings
   */
  async updateSettings(id: string, settings: Record<string, any>): Promise<void> {
    return this.put<void>(`/v1/organizations/${id}/settings`, settings);
  }

  /**
   * Get organization users
   */
  async getUsers(id: string, options?: ListOptions): Promise<any[]> {
    return this.get<any[]>(`/v1/organizations/${id}/users`, { params: options });
  }

  /**
   * Grant user access to organization
   */
  async grantUserAccess(organizationId: string, userId: string): Promise<void> {
    return this.post<void>(`/v1/organizations/${organizationId}/users`, {
      user_id: userId,
    });
  }

  /**
   * Get organization applications
   */
  async getApplications(id: string, options?: ListOptions): Promise<any[]> {
    return this.get<any[]>(`/v1/organizations/${id}/applications`, {
      params: options,
    });
  }

  /**
   * Get organization analytics
   */
  async getAnalytics(id: string): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/analytics`);
  }

  /**
   * Get user metrics
   */
  async getUserMetrics(id: string): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/metrics/users`);
  }

  /**
   * Get application metrics
   */
  async getApplicationMetrics(id: string): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/metrics/applications`);
  }

  /**
   * Get security metrics
   */
  async getSecurityMetrics(id: string): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/metrics/security`);
  }

  /**
   * Export organization data
   */
  async export(id: string, format: 'csv' | 'json' | 'excel' = 'json'): Promise<Blob> {
    return this.post<Blob>(`/v1/organizations/${id}/export`, { format });
  }

  /**
   * Get organization invitations
   */
  async getInvitations(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/organizations/${id}/invitations`);
  }

  /**
   * Create invitation
   */
  async createInvitation(id: string, email: string, role?: string): Promise<any> {
    return this.post<any>(`/v1/organizations/${id}/invitations`, { email, role });
  }

  /**
   * Delete invitation
   */
  async deleteInvitation(organizationId: string, invitationId: string): Promise<void> {
    return this.delete<void>(
      `/v1/organizations/${organizationId}/invitations/${invitationId}`
    );
  }

  /**
   * Resend invitation
   */
  async resendInvitation(organizationId: string, invitationId: string): Promise<void> {
    return this.post<void>(
      `/v1/organizations/${organizationId}/invitations/${invitationId}/resend`
    );
  }

  /**
   * Bulk invite users
   */
  async bulkInvite(id: string, emails: string[], role?: string): Promise<any> {
    return this.post<any>(`/v1/organizations/${id}/invitations/bulk`, {
      emails,
      role,
    });
  }

  /**
   * Get custom roles
   */
  async getCustomRoles(id: string): Promise<any[]> {
    return this.get<any[]>(`/v1/organizations/${id}/custom-roles`);
  }

  /**
   * Create custom role
   */
  async createCustomRole(
    id: string,
    data: { name: string; permissions: string[] }
  ): Promise<any> {
    return this.post<any>(`/v1/organizations/${id}/custom-roles`, data);
  }

  /**
   * Update custom role
   */
  async updateCustomRole(
    organizationId: string,
    roleId: string,
    data: { name?: string; permissions?: string[] }
  ): Promise<any> {
    return this.put<any>(
      `/v1/organizations/${organizationId}/custom-roles/${roleId}`,
      data
    );
  }

  /**
   * Delete custom role
   */
  async deleteCustomRole(organizationId: string, roleId: string): Promise<void> {
    return this.delete<void>(
      `/v1/organizations/${organizationId}/custom-roles/${roleId}`
    );
  }

  /**
   * Get user activity report
   */
  async getUserActivityReport(id: string, params?: any): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/reports/user-activity`, {
      params,
    });
  }

  /**
   * Get application usage report
   */
  async getApplicationUsageReport(id: string, params?: any): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/reports/application-usage`, {
      params,
    });
  }

  /**
   * Get security audit report
   */
  async getSecurityAuditReport(id: string, params?: any): Promise<any> {
    return this.get<any>(`/v1/organizations/${id}/reports/security-audit`, {
      params,
    });
  }
}
