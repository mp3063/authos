import {AuthClient} from '../src/client';

// Mock fetch
global.fetch = jest.fn();

describe('OAuth Flow', () => {
  let client: AuthClient;

  beforeEach(() => {
    client = new AuthClient({
      baseUrl: 'https://auth.example.com',
      clientId: 'test-client-id',
      redirectUri: 'https://app.example.com/callback',
    });
    (fetch as jest.Mock).mockClear();
  });

  describe('Authorization Code Flow', () => {
    it('should generate correct authorization URL', async () => {
      const url = await client.getAuthorizationUrl({
        scope: 'openid profile email',
        state: 'random-state',
      });

      const urlObj = new URL(url);

      expect(urlObj.pathname).toBe('/oauth/authorize');
      expect(urlObj.searchParams.get('client_id')).toBe('test-client-id');
      expect(urlObj.searchParams.get('response_type')).toBe('code');
      expect(urlObj.searchParams.get('redirect_uri')).toBe('https://app.example.com/callback');
      expect(urlObj.searchParams.get('scope')).toBe('openid profile email');
      expect(urlObj.searchParams.get('state')).toBe('random-state');
    });

    it('should include PKCE parameters', async () => {
      const url = await client.getAuthorizationUrl();

      const urlObj = new URL(url);

      expect(urlObj.searchParams.get('code_challenge')).toBeTruthy();
      expect(urlObj.searchParams.get('code_challenge_method')).toBe('S256');
    });
  });

  describe('Token Management', () => {
    it('should exchange authorization code for tokens', async () => {
      const mockResponse = {
        access_token: 'access-token-123',
        refresh_token: 'refresh-token-123',
        id_token: 'id-token-123',
        expires_in: 3600,
        token_type: 'Bearer',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await client.handleCallback({
        code: 'auth-code-123',
      });

      expect(result.accessToken).toBe('access-token-123');
      expect(result.refreshToken).toBe('refresh-token-123');
      expect(result.idToken).toBe('id-token-123');
    });

    it('should handle token refresh', async () => {
      client.storage.setRefreshToken('refresh-token-123');

      const mockResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await client.refreshToken();

      expect(result.accessToken).toBe('new-access-token');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/token',
        expect.objectContaining({
          body: expect.stringContaining('grant_type=refresh_token'),
        })
      );
    });

    it('should validate token expiry', () => {
      const expiredToken = {
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      };

      const validToken = {
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      };

      expect(client.isTokenExpired(expiredToken)).toBe(true);
      expect(client.isTokenExpired(validToken)).toBe(false);
    });
  });

  describe('User Info', () => {
    it('should fetch user info with access token', async () => {
      client.storage.setToken('access-token-123');

      const mockUserInfo = {
        sub: 'user-123',
        email: 'user@example.com',
        name: 'Test User',
        email_verified: true,
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockUserInfo,
      });

      const userInfo = await client.getUserInfo();

      expect(userInfo.sub).toBe('user-123');
      expect(userInfo.email).toBe('user@example.com');
      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/userinfo',
        expect.objectContaining({
          headers: {
            Authorization: 'Bearer access-token-123',
          },
        })
      );
    });

    it('should throw error if no access token', async () => {
      await expect(client.getUserInfo()).rejects.toThrow('No access token available');
    });
  });

  describe('Token Introspection', () => {
    it('should introspect token', async () => {
      const mockResponse = {
        active: true,
        scope: 'openid profile email',
        client_id: 'test-client-id',
        username: 'user@example.com',
        exp: 1234567890,
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await client.introspectToken('token-to-introspect');

      expect(result.active).toBe(true);
      expect(result.scope).toBe('openid profile email');
    });
  });

  describe('Token Revocation', () => {
    it('should revoke access token', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
      });

      await client.revokeToken('access-token-123', 'access_token');

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/token/revoke',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('token=access-token-123'),
        })
      );
    });

    it('should revoke refresh token', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
      });

      await client.revokeToken('refresh-token-123', 'refresh_token');

      expect(fetch).toHaveBeenCalledWith(
        'https://auth.example.com/oauth/token/revoke',
        expect.objectContaining({
          body: expect.stringContaining('token_type_hint=refresh_token'),
        })
      );
    });
  });

  describe('ID Token Validation', () => {
    it('should decode ID token', () => {
      const idToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature';

      const decoded = client.decodeIdToken(idToken);

      expect(decoded.sub).toBe('1234567890');
      expect(decoded.name).toBe('John Doe');
    });

    it('should validate ID token claims', () => {
      const claims = {
        iss: 'https://auth.example.com',
        aud: 'test-client-id',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      const isValid = client.validateIdTokenClaims(claims, {
        issuer: 'https://auth.example.com',
        audience: 'test-client-id',
      });

      expect(isValid).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle OAuth errors in callback', async () => {
      await expect(
        client.handleCallback({
          error: 'access_denied',
          error_description: 'User denied access',
        })
      ).rejects.toThrow('User denied access');
    });

    it('should handle network errors gracefully', async () => {
      (fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      await expect(
        client.handleCallback({ code: 'code-123' })
      ).rejects.toThrow('Network error');
    });
  });
});
