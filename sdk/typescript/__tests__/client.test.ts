import {AuthClient, AuthClientConfig} from '../src/client';
import {TokenStorage} from '../src/storage';

// Mock fetch
global.fetch = jest.fn();

describe('AuthClient', () => {
  let client: AuthClient;
  let mockStorage: TokenStorage;

  beforeEach(() => {
    mockStorage = {
      getToken: jest.fn(),
      setToken: jest.fn(),
      removeToken: jest.fn(),
      getRefreshToken: jest.fn(),
      setRefreshToken: jest.fn(),
      removeRefreshToken: jest.fn(),
    };

    const config: AuthClientConfig = {
      baseUrl: 'https://auth.example.com',
      clientId: 'test-client-id',
      redirectUri: 'https://app.example.com/callback',
      storage: mockStorage,
    };

    client = new AuthClient(config);
    (fetch as jest.Mock).mockClear();
  });

  describe('Initialization', () => {
    it('should initialize with correct config', () => {
      expect(client.config.baseUrl).toBe('https://auth.example.com');
      expect(client.config.clientId).toBe('test-client-id');
    });

    it('should use default storage if none provided', () => {
      const clientWithoutStorage = new AuthClient({
        baseUrl: 'https://auth.example.com',
        clientId: 'test-client-id',
        redirectUri: 'https://app.example.com/callback',
      });

      expect(clientWithoutStorage.storage).toBeDefined();
    });
  });

  describe('Login Flow', () => {
    it('should generate authorization URL with PKCE', async () => {
      const url = await client.getAuthorizationUrl({
        scope: 'openid profile email',
      });

      expect(url).toContain('https://auth.example.com/oauth/authorize');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('response_type=code');
      expect(url).toContain('code_challenge_method=S256');
      expect(url).toContain('code_challenge=');
    });

    it('should include state in authorization URL', async () => {
      const url = await client.getAuthorizationUrl({
        state: 'custom-state-value',
      });

      expect(url).toContain('state=custom-state-value');
    });
  });

  describe('Handle Callback', () => {
    it('should exchange code for tokens', async () => {
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse,
      });

      const result = await client.handleCallback({
        code: 'auth-code-123',
        state: 'state-123',
      });

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/token',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
        })
      );

      expect(result.accessToken).toBe('mock-access-token');
      expect(mockStorage.setToken).toHaveBeenCalledWith('mock-access-token');
      expect(mockStorage.setRefreshToken).toHaveBeenCalledWith('mock-refresh-token');
    });

    it('should throw error on failed token exchange', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'invalid_grant' }),
      });

      await expect(
        client.handleCallback({
          code: 'invalid-code',
          state: 'state-123',
        })
      ).rejects.toThrow();
    });
  });

  describe('Token Refresh', () => {
    it('should refresh access token using refresh token', async () => {
      (mockStorage.getRefreshToken as jest.Mock).mockReturnValue('refresh-token-123');

      const mockTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse,
      });

      const result = await client.refreshToken();

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/token',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('grant_type=refresh_token'),
        })
      );

      expect(result.accessToken).toBe('new-access-token');
      expect(mockStorage.setToken).toHaveBeenCalledWith('new-access-token');
    });

    it('should throw error if no refresh token available', async () => {
      (mockStorage.getRefreshToken as jest.Mock).mockReturnValue(null);

      await expect(client.refreshToken()).rejects.toThrow('No refresh token available');
    });
  });

  describe('Logout', () => {
    it('should clear tokens on logout', async () => {
      await client.logout();

      expect(mockStorage.removeToken).toHaveBeenCalled();
      expect(mockStorage.removeRefreshToken).toHaveBeenCalled();
    });

    it('should call logout endpoint if configured', async () => {
      (mockStorage.getToken as jest.Mock).mockReturnValue('access-token-123');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
      });

      await client.logout({ callServer: true });

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/auth/logout',
        expect.objectContaining({
          method: 'POST',
          headers: {
            Authorization: 'Bearer access-token-123',
          },
        })
      );
    });
  });

  describe('API Calls', () => {
    it('should make authenticated API calls', async () => {
      (mockStorage.getToken as jest.Mock).mockReturnValue('access-token-123');

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 1, name: 'Test' } }),
      });

      const result = await client.api.get('/users/me');

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/users/me',
        expect.objectContaining({
          headers: {
            Authorization: 'Bearer access-token-123',
            'Content-Type': 'application/json',
          },
        })
      );

      expect(result.data.id).toBe(1);
    });

    it('should auto-refresh token on 401 response', async () => {
      (mockStorage.getToken as jest.Mock).mockReturnValue('expired-token');
      (mockStorage.getRefreshToken as jest.Mock).mockReturnValue('refresh-token-123');

      // First call fails with 401
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'token_expired' }),
      });

      // Token refresh succeeds
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'new-token',
          refresh_token: 'new-refresh-token',
        }),
      });

      // Retry succeeds
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 1 } }),
      });

      const result = await client.api.get('/users/me');

      expect(fetch).toHaveBeenCalledTimes(3);
      expect(result.data.id).toBe(1);
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors', async () => {
      (fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      await expect(client.api.get('/users/me')).rejects.toThrow('Network error');
    });

    it('should handle API errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({
          error: 'validation_error',
          message: 'Invalid input',
        }),
      });

      await expect(client.api.post('/users', {})).rejects.toThrow();
    });
  });

  describe('PKCE Generation', () => {
    it('should generate code verifier', () => {
      const verifier = client.generateCodeVerifier();

      expect(verifier).toHaveLength(128);
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate code challenge from verifier', async () => {
      const verifier = 'test-code-verifier-12345';
      const challenge = await client.generateCodeChallenge(verifier);

      expect(challenge).toBeTruthy();
      expect(challenge).not.toBe(verifier);
    });
  });

  describe('Token Storage', () => {
    it('should store tokens after successful authentication', async () => {
      const mockTokenResponse = {
        access_token: 'access-123',
        refresh_token: 'refresh-123',
        expires_in: 3600,
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse,
      });

      await client.handleCallback({ code: 'code-123' });

      expect(mockStorage.setToken).toHaveBeenCalledWith('access-123');
      expect(mockStorage.setRefreshToken).toHaveBeenCalledWith('refresh-123');
    });

    it('should retrieve stored tokens', () => {
      (mockStorage.getToken as jest.Mock).mockReturnValue('stored-token');

      const token = client.getAccessToken();

      expect(token).toBe('stored-token');
      expect(mockStorage.getToken).toHaveBeenCalled();
    });
  });
});
