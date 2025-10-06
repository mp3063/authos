/**
 * Basic usage examples for AuthOS TypeScript SDK
 */

import {AuthOSClient} from '../src';
// Example 8: Custom Storage
import {MemoryStorage} from '../src/utils/storage';

// Example 1: Browser OAuth Flow
async function browserExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    redirectUri: 'http://localhost:3000/callback',
    scopes: ['openid', 'profile', 'email'],
  });

  // Initiate OAuth flow - this will redirect the browser
  await client.auth.initiateOAuthFlow();
}

// Example 2: Handle OAuth Callback
async function callbackExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    redirectUri: 'http://localhost:3000/callback',
  });

  // Handle the callback (call this on your callback page)
  const tokens = await client.auth.handleCallback();
  console.log('Access token:', tokens.access_token);

  // Get current user
  const user = await client.auth.getUser();
  console.log('Logged in as:', user.name, user.email);
}

// Example 3: Server-side with Credentials
async function serverExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret', // Only on server!
  });

  // Login with credentials
  const tokens = await client.auth.login({
    email: 'user@example.com',
    password: 'password123',
  });

  console.log('Logged in, token expires in:', tokens.expires_in, 'seconds');
}

// Example 4: User Management
async function userManagementExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  // Login first
  await client.auth.login({
    email: 'admin@example.com',
    password: 'admin123',
  });

  // List users
  const usersResponse = await client.users.list({
    page: 1,
    per_page: 20,
  });

  console.log('Total users:', usersResponse.meta.total);
  usersResponse.data.forEach((user) => {
    console.log(`- ${user.name} (${user.email})`);
  });

  // Create a new user
  const newUser = await client.users.create({
    name: 'John Doe',
    email: 'john@example.com',
    password: 'secure-password',
  });

  console.log('Created user:', newUser.id);

  // Update user
  await client.users.update(newUser.id, {
    name: 'John Smith',
  });

  // Delete user
  await client.users.delete(newUser.id);
}

// Example 5: Organization Management
async function organizationExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  await client.auth.login({
    email: 'admin@example.com',
    password: 'admin123',
  });

  // Create organization
  const org = await client.organizations.create({
    name: 'Acme Corporation',
    slug: 'acme-corp',
    settings: {
      mfa_required: true,
      session_timeout: 3600,
    },
  });

  console.log('Created organization:', org.id);

  // Get analytics
  const analytics = await client.organizations.getAnalytics(org.id);
  console.log('Total users:', analytics.total_users);
  console.log('Active users:', analytics.active_users);

  // Invite users
  await client.organizations.createInvitation(org.id, 'user@example.com', 'admin');

  // Bulk invite
  await client.organizations.bulkInvite(org.id, [
    'user1@example.com',
    'user2@example.com',
    'user3@example.com',
  ]);
}

// Example 6: Application Management
async function applicationExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  await client.auth.login({
    email: 'admin@example.com',
    password: 'admin123',
  });

  // Create OAuth application
  const app = await client.applications.create({
    name: 'My Mobile App',
    redirect_uris: ['myapp://callback', 'http://localhost:3000/callback'],
  });

  console.log('Client ID:', app.client_id);

  // Regenerate credentials (returns new secret)
  const credentials = await client.applications.regenerateCredentials(app.id);
  console.log('New Client Secret:', credentials.client_secret);
  console.warn('Store this secret securely - it will not be shown again!');

  // Get application analytics
  const appAnalytics = await client.applications.getAnalytics(app.id);
  console.log('Total authentications:', appAnalytics.total_authentications);
  console.log('Active users:', appAnalytics.active_users);
}

// Example 7: Error Handling
async function errorHandlingExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  try {
    await client.auth.login({
      email: 'user@example.com',
      password: 'wrong-password',
    });
  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error('Authentication failed:', error.message);
      // Show error to user
    } else if (error instanceof ValidationError) {
      console.error('Validation errors:', error.errors);
      // { email: ['The email field is required'], password: [...] }
    } else if (error instanceof RateLimitError) {
      console.error('Too many requests. Retry after:', error.retryAfter, 'seconds');
      // Implement exponential backoff
    } else if (error instanceof NetworkError) {
      console.error('Network error:', error.message);
      // Retry or show offline message
    }
  }
}

async function customStorageExample() {
  // Use memory storage (tokens lost on page refresh)
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    storage: new MemoryStorage(),
  });

  // Custom storage implementation
  class CustomStorage {
    async getItem(key: string): Promise<string | null> {
      // Your implementation (e.g., secure encrypted storage)
      return null;
    }

    async setItem(key: string, value: string): Promise<void> {
      // Your implementation
    }

    async removeItem(key: string): Promise<void> {
      // Your implementation
    }
  }

  const secureClient = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    storage: new CustomStorage(),
  });
}

// Example 9: Check Authentication Status
async function authStatusExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  // Check if user is authenticated
  const isAuthenticated = await client.auth.isAuthenticated();

  if (isAuthenticated) {
    const user = await client.auth.getUser();
    console.log('Logged in as:', user.name);
  } else {
    console.log('Not authenticated');
    // Redirect to login
  }
}

// Example 10: Token Management
async function tokenManagementExample() {
  const client = new AuthOSClient({
    baseUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
  });

  await client.auth.login({
    email: 'user@example.com',
    password: 'password123',
  });

  // Get token manager
  const tokenManager = client.auth.getTokenManager();

  // Get token info
  const tokenInfo = await tokenManager.getTokenInfo();
  if (tokenInfo) {
    console.log('Token expires in:', tokenInfo.expires_in, 'seconds');
    console.log('Token expires at:', new Date(tokenInfo.expires_at));
  }

  // Manually refresh token
  await client.auth.refreshToken();
  console.log('Token refreshed');

  // Token is automatically refreshed when needed
  // No manual intervention required!
}

// Export examples
export {
  browserExample,
  callbackExample,
  serverExample,
  userManagementExample,
  organizationExample,
  applicationExample,
  errorHandlingExample,
  customStorageExample,
  authStatusExample,
  tokenManagementExample,
};
