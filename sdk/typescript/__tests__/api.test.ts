import {AuthClient} from '../src/client';
import {ApplicationsApi, OrganizationsApi, UsersApi} from '../src/api';

// Mock fetch
global.fetch = jest.fn();

describe('API Client', () => {
  let client: AuthClient;

  beforeEach(() => {
    client = new AuthClient({
      baseUrl: 'https://auth.example.com',
      clientId: 'test-client-id',
      redirectUri: 'https://app.example.com/callback',
    });
    client.storage.setToken('access-token-123');
    (fetch as jest.Mock).mockClear();
  });

  describe('Users API', () => {
    let usersApi: UsersApi;

    beforeEach(() => {
      usersApi = new UsersApi(client);
    });

    it('should fetch current user', async () => {
      const mockUser = {
        id: 1,
        email: 'user@example.com',
        name: 'Test User',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: mockUser }),
      });

      const user = await usersApi.getCurrentUser();

      expect(user.id).toBe(1);
      expect(user.email).toBe('user@example.com');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/users/me',
        expect.any(Object)
      );
    });

    it('should list users with pagination', async () => {
      const mockResponse = {
        data: [
          { id: 1, email: 'user1@example.com' },
          { id: 2, email: 'user2@example.com' },
        ],
        meta: {
          pagination: {
            current_page: 1,
            total: 2,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await usersApi.list({ page: 1, per_page: 10 });

      expect(result.data).toHaveLength(2);
      expect(result.meta.pagination.current_page).toBe(1);
    });

    it('should create user', async () => {
      const newUser = {
        email: 'newuser@example.com',
        name: 'New User',
        password: 'password123',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 3, ...newUser } }),
      });

      const user = await usersApi.create(newUser);

      expect(user.id).toBe(3);
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/users',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(newUser),
        })
      );
    });

    it('should update user', async () => {
      const updates = { name: 'Updated Name' };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 1, ...updates } }),
      });

      const user = await usersApi.update(1, updates);

      expect(user.name).toBe('Updated Name');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/users/1',
        expect.objectContaining({
          method: 'PUT',
        })
      );
    });

    it('should delete user', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
      });

      await usersApi.delete(1);

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/users/1',
        expect.objectContaining({
          method: 'DELETE',
        })
      );
    });
  });

  describe('Organizations API', () => {
    let orgsApi: OrganizationsApi;

    beforeEach(() => {
      orgsApi = new OrganizationsApi(client);
    });

    it('should fetch current organization', async () => {
      const mockOrg = {
        id: 1,
        name: 'Test Organization',
        slug: 'test-org',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: mockOrg }),
      });

      const org = await orgsApi.getCurrent();

      expect(org.id).toBe(1);
      expect(org.name).toBe('Test Organization');
    });

    it('should list organization users', async () => {
      const mockUsers = {
        data: [
          { id: 1, email: 'user1@example.com' },
          { id: 2, email: 'user2@example.com' },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockUsers,
      });

      const users = await orgsApi.listUsers(1);

      expect(users.data).toHaveLength(2);
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/organizations/1/users',
        expect.any(Object)
      );
    });

    it('should update organization settings', async () => {
      const settings = {
        require_mfa: true,
        session_timeout: 3600,
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 1, settings } }),
      });

      const org = await orgsApi.updateSettings(1, settings);

      expect(org.settings.require_mfa).toBe(true);
    });

    it('should invite user to organization', async () => {
      const invitation = {
        email: 'newuser@example.com',
        role: 'user',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 'inv-123', ...invitation } }),
      });

      const result = await orgsApi.inviteUser(1, invitation);

      expect(result.email).toBe('newuser@example.com');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/organizations/1/invitations',
        expect.objectContaining({
          method: 'POST',
        })
      );
    });
  });

  describe('Applications API', () => {
    let appsApi: ApplicationsApi;

    beforeEach(() => {
      appsApi = new ApplicationsApi(client);
    });

    it('should list applications', async () => {
      const mockApps = {
        data: [
          { id: 1, name: 'App 1', client_id: 'client-1' },
          { id: 2, name: 'App 2', client_id: 'client-2' },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockApps,
      });

      const apps = await appsApi.list();

      expect(apps.data).toHaveLength(2);
    });

    it('should create application', async () => {
      const newApp = {
        name: 'New App',
        redirect_uris: ['https://app.example.com/callback'],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            id: 3,
            ...newApp,
            client_id: 'new-client-id',
            client_secret: 'new-client-secret',
          },
        }),
      });

      const app = await appsApi.create(newApp);

      expect(app.id).toBe(3);
      expect(app.client_id).toBe('new-client-id');
    });

    it('should regenerate application credentials', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            client_id: 'new-client-id',
            client_secret: 'new-client-secret',
          },
        }),
      });

      const credentials = await appsApi.regenerateCredentials(1);

      expect(credentials.client_id).toBe('new-client-id');
      expect(credentials.client_secret).toBe('new-client-secret');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/applications/1/regenerate-credentials',
        expect.objectContaining({
          method: 'POST',
        })
      );
    });

    it('should get application analytics', async () => {
      const mockAnalytics = {
        data: {
          total_users: 100,
          active_sessions: 50,
          daily_logins: [
            { date: '2024-01-01', count: 10 },
            { date: '2024-01-02', count: 15 },
          ],
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAnalytics,
      });

      const analytics = await appsApi.getAnalytics(1);

      expect(analytics.data.total_users).toBe(100);
    });
  });

  describe('Error Handling', () => {
    let usersApi: UsersApi;

    beforeEach(() => {
      usersApi = new UsersApi(client);
    });

    it('should handle 404 errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: 'not_found', message: 'User not found' }),
      });

      await expect(usersApi.get(999)).rejects.toThrow('User not found');
    });

    it('should handle validation errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 422,
        json: async () => ({
          error: 'validation_error',
          errors: {
            email: ['The email field is required'],
          },
        }),
      });

      await expect(usersApi.create({ name: 'Test' })).rejects.toThrow();
    });

    it('should handle network errors', async () => {
      (fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      await expect(usersApi.list()).rejects.toThrow('Network error');
    });

    it('should handle unauthorized errors', async () => {
      client.storage.removeToken();

      await expect(usersApi.getCurrentUser()).rejects.toThrow('No access token');
    });
  });
});
