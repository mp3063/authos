# AuthOS SDKs

Official SDKs for AuthOS - Enterprise authentication service.

## Available SDKs

### TypeScript/JavaScript SDK

**Status:** ✅ Production Ready

Full-featured TypeScript SDK with comprehensive type definitions and automatic token management.

- **Package:** `@authos/client`
- **Installation:** `npm install @authos/client`
- **Documentation:** [TypeScript SDK Docs](./typescript/README.md)
- **Bundle Size:** < 50KB gzipped
- **Browser:** ✅ Chrome, Firefox, Safari, Edge
- **Node.js:** ✅ 18+

**Features:**
- ✅ Full TypeScript support with IntelliSense
- ✅ OAuth 2.0 + PKCE flow
- ✅ Automatic token refresh
- ✅ Configurable storage adapters
- ✅ Tree-shakeable ESM/CJS builds
- ✅ 100% type coverage

### Python SDK

**Status:** 🔄 Generated from OpenAPI

Python SDK generated from OpenAPI specification with custom auth helpers.

- **Package:** `authos-client`
- **Installation:** `pip install authos-client`
- **Documentation:** [Python SDK Docs](./python/README.md)
- **Python:** 3.9+

**Features:**
- ✅ Auto-generated from OpenAPI spec
- ✅ PKCE support
- ✅ OAuth helpers
- ✅ Type hints
- ✅ Async support

### PHP SDK

**Status:** 🔄 Generated from OpenAPI

PHP SDK compatible with Laravel and standalone applications.

- **Package:** `authos/client`
- **Installation:** `composer require authos/client`
- **Documentation:** [PHP SDK Docs](./php/README.md)
- **PHP:** 8.2+

**Features:**
- ✅ Auto-generated from OpenAPI spec
- ✅ PKCE support
- ✅ OAuth helpers
- ✅ Laravel integration
- ✅ PSR-7 compatible

## Quick Start

### TypeScript/JavaScript

```typescript
import { AuthOSClient } from '@authos/client';

const client = new AuthOSClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:3000/callback',
});

// OAuth login
await client.auth.initiateOAuthFlow();

// After callback
await client.auth.handleCallback();

// Get user
const user = await client.auth.getUser();
```

### Python

```python
from authos_client import Client
from authos_client.auth import OAuthHelper

client = Client(base_url="https://auth.example.com")

oauth = OAuthHelper(
    client_id="your-client-id",
    redirect_uri="http://localhost:8000/callback",
    base_url="https://auth.example.com"
)

# Get authorization URL
auth_url, state, code_verifier = oauth.get_authorization_url()
```

### PHP

```php
use AuthOS\Client\Configuration;
use AuthOS\Client\ApiClient;
use AuthOS\Client\Auth\OAuthHelper;

$config = Configuration::getDefaultConfiguration();
$config->setHost('https://auth.example.com');

$apiClient = new ApiClient($config);

$oauth = new OAuthHelper(
    clientId: 'your-client-id',
    redirectUri: 'http://localhost:8000/callback',
    baseUrl: 'https://auth.example.com'
);

$authData = $oauth->getAuthorizationUrl();
```

## SDK Generation

### Generate OpenAPI Specification

```bash
herd php artisan openapi:generate --validate
```

This creates `public/openapi.json` with all 144+ API endpoints.

### Generate Python SDK

```bash
./sdk/scripts/generate-python-sdk.sh
```

### Generate PHP SDK

```bash
./sdk/scripts/generate-php-sdk.sh
```

**Requirements:**
- OpenAPI Generator: `brew install openapi-generator`

## Development

### TypeScript SDK

```bash
cd sdk/typescript

# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Run tests
npm test

# Lint
npm run lint
```

### Python SDK

```bash
cd sdk/python

# Install in development mode
pip install -e .

# Run tests
pytest

# Format code
black .
```

### PHP SDK

```bash
cd sdk/php

# Install dependencies
composer install

# Run tests
composer test

# Fix code style
composer cs-fix
```

## CI/CD

The SDK release workflow automatically:

1. Generates OpenAPI specification
2. Builds TypeScript SDK
3. Runs tests and linting
4. Publishes to NPM (on version tags)
5. Generates Python SDK
6. Publishes to PyPI (on version tags)
7. Generates PHP SDK
8. Creates GitHub release with all artifacts

**Trigger a release:**

```bash
# Tag and push
git tag v1.0.0
git push origin v1.0.0

# Or use GitHub UI
# Actions → SDK Release → Run workflow
```

## Architecture

### TypeScript SDK Structure

```
sdk/typescript/
├── src/
│   ├── index.ts              # Main export
│   ├── client.ts             # AuthOSClient
│   ├── auth/
│   │   ├── AuthService.ts    # OAuth flow
│   │   └── TokenManager.ts   # Token management
│   ├── api/
│   │   ├── BaseAPI.ts        # HTTP client
│   │   ├── UsersAPI.ts       # Users endpoints
│   │   ├── OrganizationsAPI.ts
│   │   └── ApplicationsAPI.ts
│   ├── types/
│   │   └── index.ts          # TypeScript types
│   ├── errors/
│   │   └── index.ts          # Error classes
│   └── utils/
│       ├── storage.ts        # Storage adapters
│       └── pkce.ts           # PKCE utilities
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

### Token Management

All SDKs implement:

- **Automatic refresh** - Tokens refreshed before expiration
- **Race condition prevention** - Single refresh promise
- **Secure storage** - Configurable storage adapters
- **Expiration handling** - 60-second buffer

### OAuth 2.0 Flow

1. **Authorization Request** - Generate PKCE challenge, redirect to auth page
2. **Authorization Grant** - User approves, receives authorization code
3. **Token Exchange** - Exchange code + verifier for access token
4. **Token Refresh** - Refresh token before expiration
5. **Token Revocation** - Logout and revoke tokens

## API Coverage

All SDKs provide access to:

- **Authentication** (12 endpoints) - Login, register, MFA, social auth
- **Users** (15 endpoints) - CRUD, roles, sessions
- **Organizations** (36 endpoints) - CRUD, settings, invitations, analytics
- **Applications** (13 endpoints) - OAuth clients, credentials, tokens
- **Profile** (9 endpoints) - User profile, preferences, security
- **MFA** (10 endpoints) - TOTP setup, recovery codes
- **SSO** (19 endpoints) - OIDC/SAML configuration
- **Enterprise** (19 endpoints) - LDAP, branding, domains, compliance

**Total: 144+ REST endpoints**

## Security

### OAuth 2.0 Best Practices

- ✅ PKCE (RFC 7636) for authorization code flow
- ✅ State parameter for CSRF protection
- ✅ Token rotation on refresh
- ✅ Secure storage recommendations
- ✅ HTTPS enforcement

### Token Storage

**Browser:**
- ✅ LocalStorage (persistent)
- ✅ SessionStorage (tab-scoped)
- ✅ Memory (no persistence)
- ❌ Avoid cookies without HttpOnly flag

**Server:**
- ✅ Environment variables
- ✅ Secure credential stores
- ✅ Session backends

## Testing

### TypeScript SDK

```bash
cd sdk/typescript
npm test                # Run tests
npm run test:coverage   # Coverage report
```

### Python SDK

```bash
cd sdk/python
pytest                  # Run tests
pytest --cov            # Coverage report
```

### PHP SDK

```bash
cd sdk/php
composer test           # Run PHPUnit
```

## Publishing

### TypeScript to NPM

```bash
cd sdk/typescript
npm version patch       # or minor/major
npm publish --access public
```

### Python to PyPI

```bash
cd sdk/python
python -m build
twine upload dist/*
```

### PHP to Packagist

1. Push to GitHub repository
2. Register on [Packagist.org](https://packagist.org)
3. Configure auto-update webhook

## Support

- **Documentation:** [https://docs.authos.dev](https://docs.authos.dev)
- **GitHub Issues:** [https://github.com/authos/authos/issues](https://github.com/authos/authos/issues)
- **Email:** support@authos.dev

## License

MIT © AuthOS Team
