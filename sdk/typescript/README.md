# AuthOS TypeScript SDK

Official TypeScript/JavaScript SDK for AuthOS - Enterprise authentication service.

[![npm version](https://badge.fury.io/js/%40authos%2Fclient.svg)](https://badge.fury.io/js/%40authos%2Fclient)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- ✅ **Full TypeScript Support** - Complete type definitions for excellent IntelliSense
- 🔐 **OAuth 2.0 + PKCE** - Secure authorization code flow with PKCE support
- 🔄 **Automatic Token Refresh** - Seamless token refresh with race condition prevention
- 🌐 **Universal** - Works in browser and Node.js environments
- 📦 **Tree-Shakeable** - Only import what you need (< 50KB gzipped)
- 🎯 **Type-Safe** - Catch errors at compile time
- 🔧 **Configurable** - Flexible configuration and custom storage adapters
- ⚡ **Modern** - ESM and CommonJS support

## Installation

```bash
npm install @authos/client
```

or

```bash
yarn add @authos/client
```

## Quick Start

### Browser Usage (OAuth 2.0 Flow)

```typescript
import { AuthOSClient } from '@authos/client';

const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:3000/callback',
  scopes: ['openid', 'profile', 'email'],
});

// Login - redirects to authorization page
await client.auth.initiateOAuthFlow();

// In your callback page
await client.auth.handleCallback();

// Get current user
const user = await client.auth.getUser();
console.log(user);
```

### Server Usage (Password Grant)

```typescript
import { AuthOSClient } from '@authos/client';

const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret', // Server-side only
});

// Login with credentials
const tokens = await client.auth.login({
  email: 'user@example.com',
  password: 'password123',
});

console.log('Access token:', tokens.access_token);
```

## Core Concepts

### Authentication

```typescript
// Register a new user
await client.auth.register({
  name: 'John Doe',
  email: 'john@example.com',
  password: 'secure-password',
});

// Login
await client.auth.login({
  email: 'john@example.com',
  password: 'secure-password',
});

// Check if authenticated
const isAuth = await client.auth.isAuthenticated();

// Get current user
const user = await client.auth.getUser();

// Logout
await client.auth.logout();
```

### User Management

```typescript
// List users
const users = await client.users.list({
  page: 1,
  per_page: 20,
  sort: 'created_at',
});

// Get user by ID
const user = await client.users.get('user-id');

// Create user
const newUser = await client.users.create({
  name: 'Jane Doe',
  email: 'jane@example.com',
  password: 'password123',
});

// Update user
await client.users.update('user-id', {
  name: 'Jane Smith',
});

// Delete user
await client.users.delete('user-id');

// User roles
await client.users.assignRole('user-id', 'role-id');
await client.users.removeRole('user-id', 'role-id');

// User sessions
const sessions = await client.users.getSessions('user-id');
await client.users.revokeSessions('user-id');
```

### Organization Management

```typescript
// List organizations
const orgs = await client.organizations.list();

// Create organization
const org = await client.organizations.create({
  name: 'Acme Corp',
  slug: 'acme-corp',
  settings: {
    mfa_required: true,
    session_timeout: 3600,
  },
});

// Get organization
const org = await client.organizations.get('org-id');

// Update settings
await client.organizations.updateSettings('org-id', {
  mfa_required: false,
});

// Analytics
const analytics = await client.organizations.getAnalytics('org-id');
const userMetrics = await client.organizations.getUserMetrics('org-id');
const securityMetrics = await client.organizations.getSecurityMetrics('org-id');

// Invitations
await client.organizations.createInvitation('org-id', 'user@example.com', 'admin');
await client.organizations.bulkInvite('org-id', ['user1@example.com', 'user2@example.com']);
```

### Application Management

```typescript
// List applications
const apps = await client.applications.list();

// Create application
const app = await client.applications.create({
  name: 'My App',
  redirect_uris: ['http://localhost:3000/callback'],
});

// Regenerate credentials
const credentials = await client.applications.regenerateCredentials('app-id');
console.log('Client ID:', credentials.client_id);
console.log('Client Secret:', credentials.client_secret);

// Application analytics
const analytics = await client.applications.getAnalytics('app-id');
```

## Advanced Usage

### Custom Storage

```typescript
import { AuthOSClient, MemoryStorage, BrowserStorage } from '@authos/client';

// Use memory storage (no persistence)
const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  storage: new MemoryStorage(),
});

// Use browser localStorage
const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  storage: new BrowserStorage('my_app_'),
});

// Custom storage implementation
class CustomStorage {
  async getItem(key: string): Promise<string | null> {
    // Your implementation
  }

  async setItem(key: string, value: string): Promise<void> {
    // Your implementation
  }

  async removeItem(key: string): Promise<void> {
    // Your implementation
  }
}

const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  storage: new CustomStorage(),
});
```

### Token Management

```typescript
// Get token manager
const tokenManager = client.auth.getTokenManager();

// Get current token info
const tokenInfo = await tokenManager.getTokenInfo();
console.log('Expires in:', tokenInfo?.expires_in, 'seconds');

// Manually refresh token
await client.auth.refreshToken();

// Check if token is expired
const isExpired = await tokenManager.isExpired();
```

### Error Handling

```typescript
import {
  AuthenticationError,
  ValidationError,
  RateLimitError,
  NetworkError,
} from '@authos/client';

try {
  await client.auth.login({ email: 'user@example.com', password: 'wrong' });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message);
  } else if (error instanceof ValidationError) {
    console.error('Validation errors:', error.errors);
  } else if (error instanceof RateLimitError) {
    console.error('Rate limited. Retry after:', error.retryAfter);
  } else if (error instanceof NetworkError) {
    console.error('Network error:', error.message);
  }
}
```

### Request Configuration

```typescript
// Custom timeout
const users = await client.users.list({}, { timeout: 5000 });

// Custom headers
const user = await client.users.get('user-id', {
  headers: { 'X-Custom-Header': 'value' },
});

// Skip authentication (for public endpoints)
const publicData = await client.users.get('user-id', {
  skipAuth: true,
});
```

## TypeScript Support

The SDK is written in TypeScript and provides complete type definitions:

```typescript
import type {
  User,
  Organization,
  Application,
  TokenResponse,
  PaginatedResponse,
} from '@authos/client';

const handleUser = (user: User) => {
  console.log(user.name); // TypeScript knows all User properties
};

const handleOrganizations = (response: PaginatedResponse<Organization>) => {
  response.data.forEach((org) => {
    console.log(org.slug); // Type-safe
  });
};
```

## Configuration Options

```typescript
interface AuthOSConfig {
  // Required
  baseUrl: string; // AuthOS server URL
  clientId: string; // OAuth client ID

  // Optional
  clientSecret?: string; // OAuth client secret (server-side only)
  redirectUri?: string; // OAuth redirect URI
  scopes?: string[]; // OAuth scopes (default: ['openid', 'profile', 'email'])
  storage?: Storage; // Custom storage adapter
  usePKCE?: boolean; // Enable PKCE (default: true)
  fetch?: typeof fetch; // Custom fetch implementation
  timeout?: number; // Request timeout in ms (default: 30000)
  autoRefresh?: boolean; // Auto-refresh tokens (default: true)
}
```

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Node.js Support

- Node.js 18+

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint
npm run lint

# Type check
npm run typecheck
```

## Examples

Check out the [examples](./examples) directory for complete working examples:

- [React App](./examples/react)
- [Next.js App](./examples/nextjs)
- [Node.js Server](./examples/nodejs)
- [Vue.js App](./examples/vue)

## API Reference

Full API reference is available at [https://docs.authos.dev/sdk/typescript](https://docs.authos.dev/sdk/typescript)

## License

MIT © AuthOS Team

## Support

- Documentation: [https://docs.authos.dev](https://docs.authos.dev)
- Issues: [https://github.com/authos/sdk-typescript/issues](https://github.com/authos/sdk-typescript/issues)
- Email: support@authos.dev
