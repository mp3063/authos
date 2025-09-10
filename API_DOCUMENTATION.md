# AuthOS API Documentation

Comprehensive API documentation for the Laravel 12 authentication service - An Auth0 alternative providing OAuth 2.0, OpenID Connect, multi-factor authentication, and single sign-on capabilities.

**Current Status**: Production-Ready with 306/306 passing tests (100% success rate) and unified API response format across all endpoints.

## 📋 Documentation Overview

This API documentation package includes:

- **OpenAPI 3.0 Specification** (`openapi.yaml`) - Complete API specification following OpenAPI standards with unified response format
- **Postman Collection** (`postman-collection.json`) - Ready-to-import collection with examples, tests, and comprehensive endpoint coverage
- **Environment Files** - Pre-configured environment variables for different deployment stages:
  - `postman-environment-development.json` - HERD development environment
  - `postman-environment-staging.json` - Staging environment configuration
  - `postman-environment-production.json` - Production environment configuration
- **Interactive Documentation** (`public/docs/index.html`) - Swagger UI interface for live API testing
- **Developer Guide** (this file) - Integration guides and best practices

## 🆕 New Features in Latest Update

- **Social Authentication Endpoints** - Complete integration with Google, GitHub, Facebook, Twitter, LinkedIn
- **Comprehensive Organization Management** - Analytics, user management, invitations, bulk operations
- **SSO (Single Sign-On)** - SAML and OAuth2 SSO configuration and session management
- **OAuth Token Introspection** - RFC 7662 compliant token validation endpoint
- **Bulk User Operations** - Mass user management capabilities
- **Enhanced Testing** - Comprehensive test scenarios with auto-validation scripts
- **Multi-Environment Support** - Pre-configured environments for seamless deployment

## 🚀 Quick Start

### 1. Access Interactive Documentation

Visit the interactive documentation at:
- **Development**: `http://authos.test/docs/`
- **Production**: `https://api.authos.dev/docs/`

### 2. Import Postman Collection

1. Download `postman-collection.json`
2. Open Postman → Import → Select the downloaded file
3. Set collection variables:
   - `baseUrl`: Your API base URL
   - `clientId`: Your OAuth client ID (from admin panel)
   - `clientSecret`: Your OAuth client secret

### 3. Test Your First Request

```bash
# Get API version info (no authentication required)
curl -X GET "http://authos.test/api/version"

# Register a new user
curl -X POST "http://authos.test/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "StrongP@ss123",
    "password_confirmation": "StrongP@ss123",
    "terms_accepted": true
  }'
```

## 🔐 Authentication Guide

### Bearer Token Authentication

All protected endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer {access_token}
```

### Getting Access Tokens

#### Method 1: User Registration/Login
```bash
# Login to get access token
curl -X POST "http://authos.test/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "StrongP@ss123",
    "scopes": ["openid", "profile", "email"]
  }'
```

#### Method 2: OAuth Authorization Code Flow
```bash
# Step 1: Get authorization code (redirect user to this URL)
https://api.authos.dev/api/v1/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https://yourapp.com/callback&scope=openid profile email&state=xyz123

# Step 2: Exchange code for token
curl -X POST "http://authos.test/api/v1/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&code=AUTHORIZATION_CODE&redirect_uri=https://yourapp.com/callback"
```

#### Method 3: Client Credentials Flow (Server-to-Server)
```bash
curl -X POST "http://authos.test/api/v1/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=read write"
```

### Token Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Basic OpenID Connect access |
| `profile` | Access to user profile information |
| `email` | Access to user email address |
| `read` | Read access to resources |
| `write` | Write access to resources |
| `admin` | Administrative access (management endpoints) |

## ⚡ Rate Limiting

Different endpoint categories have specific rate limits:

| Category | Limit | Window | Basis |
|----------|--------|---------|-------|
| Authentication | 10 requests | 1 minute | Per IP |
| Registration | 5 requests | 1 hour | Per IP |
| Standard API | 1000 requests | 1 hour | Per User |
| Admin API | 200 requests | 1 hour | Per User |
| Bulk Operations | 100 requests | 1 hour | Per User |
| MFA | 20 requests | 1 hour | Per User |
| OAuth | 20 requests | 1 minute | Per IP |

### Rate Limit Headers

All responses include rate limiting information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1693012800
X-RateLimit-Window: 3600
```

### Role-based Rate Limit Multipliers

Users with elevated roles receive increased rate limits:
- **Super Admin**: 5x base limit
- **Organization Admin**: 3x base limit  
- **Application Admin**: 2x base limit

## 🏗️ API Architecture

### Base URLs

- **Production**: `https://api.authos.dev/api/v1`
- **Staging**: `https://staging-api.authos.dev/api/v1`
- **Development**: `http://authos.test/api/v1`

### Response Format

#### Success Response
```json
{
  "data": {
    // Response data
  },
  "meta": {
    "pagination": {
      "current_page": 1,
      "per_page": 15,
      "total": 100,
      "total_pages": 7
    }
  },
  "links": {
    "self": "/api/v1/users?page=1",
    "next": "/api/v1/users?page=2",
    "prev": null
  }
}
```

#### Error Response
```json
{
  "error": "validation_failed",
  "error_description": "The given data was invalid.",
  "details": {
    "email": ["The email field is required."]
  }
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request parameters |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 422 | Unprocessable Entity - Validation failed |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

## 🛠️ SDK Generation

The OpenAPI specification can be used to generate SDKs for various programming languages:

### JavaScript/TypeScript
```bash
npx @openapitools/openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o ./sdk/javascript
```

### Python
```bash
openapi-generator-cli generate \
  -i openapi.yaml \
  -g python \
  -o ./sdk/python \
  --additional-properties packageName=authos_api
```

### PHP
```bash
openapi-generator-cli generate \
  -i openapi.yaml \
  -g php \
  -o ./sdk/php \
  --additional-properties packageName=AuthosApi
```

### Go
```bash
openapi-generator-cli generate \
  -i openapi.yaml \
  -g go \
  -o ./sdk/go \
  --additional-properties packageName=authos
```

## 🎯 Common Integration Patterns

### 1. Single Page Application (SPA)

For frontend applications using React, Vue, Angular:

```javascript
// Example using axios
const api = axios.create({
  baseURL: 'https://api.authos.dev/api/v1',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Login and store token
async function login(email, password) {
  const response = await api.post('/auth/login', {
    email,
    password,
    scopes: ['openid', 'profile', 'email']
  });
  
  localStorage.setItem('access_token', response.data.access_token);
  return response.data;
}
```

### 2. Server-side Application

For server-side applications (Node.js, Python, PHP):

```javascript
// Node.js example
const fetch = require('node-fetch');

class AuthosClient {
  constructor(clientId, clientSecret, baseUrl = 'https://api.authos.dev/api/v1') {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.baseUrl = baseUrl;
    this.accessToken = null;
  }

  async getClientCredentialsToken() {
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: 'read write'
      })
    });
    
    const data = await response.json();
    this.accessToken = data.access_token;
    return data;
  }

  async apiRequest(endpoint, options = {}) {
    if (!this.accessToken) {
      await this.getClientCredentialsToken();
    }

    return fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
  }
}
```

### 3. Mobile Application

For mobile apps using OAuth PKCE flow:

```swift
// iOS Swift example
import Foundation
import CryptoKit

class AuthosSDK {
    private let clientId: String
    private let baseURL = "https://api.authos.dev/api/v1"
    
    init(clientId: String) {
        self.clientId = clientId
    }
    
    // Generate PKCE parameters
    func generatePKCE() -> (verifier: String, challenge: String) {
        let verifier = generateCodeVerifier()
        let challenge = generateCodeChallenge(from: verifier)
        return (verifier, challenge)
    }
    
    // Build authorization URL
    func buildAuthorizationURL(redirectURI: String, state: String, codeChallenge: String) -> URL? {
        var components = URLComponents(string: "\(baseURL)/oauth/authorize")
        components?.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        return components?.url
    }
}
```

## 🧪 Testing & Development

### Using Postman

1. Import the collection (`postman-collection.json`)
2. Set up environment variables:
   - `baseUrl`: `http://authos.test/api/v1`
   - `accessToken`: Will be auto-populated after login
3. Run authentication requests first to get tokens
4. Use the "Tests" tab in Postman to verify responses

### Using cURL Examples

```bash
# Test rate limiting
for i in {1..5}; do
  curl -w "Status: %{http_code}, Time: %{time_total}s\n" \
    -X POST "http://authos.test/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"wrong@email.com","password":"wrong"}'
  sleep 1
done

# Test pagination
curl -X GET "http://authos.test/api/v1/users?page=1&per_page=5" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Test search functionality
curl -X GET "http://authos.test/api/v1/users?search=john&sort=name" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Error Testing

Test error scenarios to ensure proper error handling:

```bash
# Test validation errors
curl -X POST "http://authos.test/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"invalid-email"}'

# Test authentication errors
curl -X GET "http://authos.test/api/v1/profile" \
  -H "Authorization: Bearer invalid_token"

# Test rate limiting
# (Make rapid requests to trigger rate limiting)
```

## 🔧 Development Tools

### Recommended Tools

1. **Postman** - API testing and collection management
2. **Insomnia** - Alternative REST client
3. **OpenAPI Generator** - SDK generation
4. **Swagger Editor** - OpenAPI specification editing
5. **Newman** - Command-line Postman collection runner

### VS Code Extensions

- REST Client
- OpenAPI (Swagger) Editor
- Postman
- Thunder Client

## 🚨 Security Considerations

### Best Practices

1. **Always use HTTPS** in production
2. **Store tokens securely** (use secure storage, not localStorage for sensitive apps)
3. **Implement proper CORS** settings
4. **Use PKCE** for public clients (mobile apps, SPAs)
5. **Rotate client secrets** regularly
6. **Monitor rate limiting** and implement backoff strategies
7. **Validate all inputs** on your client side
8. **Handle token expiration** gracefully

### Token Storage

```javascript
// ✅ Good: Secure storage
const token = await SecureStore.getItemAsync('access_token');

// ❌ Bad: Insecure storage (for sensitive apps)
const token = localStorage.getItem('access_token');
```

### Error Handling

```javascript
// ✅ Good: Proper error handling
try {
  const response = await api.get('/profile');
  return response.data;
} catch (error) {
  if (error.response?.status === 401) {
    // Token expired, redirect to login
    redirectToLogin();
  } else if (error.response?.status === 429) {
    // Rate limited, implement backoff
    await delay(error.response.headers['retry-after'] * 1000);
    return retryRequest();
  }
  throw error;
}
```

## 📞 Support & Resources

- **Documentation**: `http://authos.test/docs/` (interactive)
- **OpenAPI Spec**: `openapi.yaml`
- **Postman Collection**: `postman-collection.json`
- **Admin Panel**: `http://authos.test/admin/`
- **GitHub Repository**: Your repository URL
- **Support Email**: support@authos.dev

## 🔄 Versioning

This API uses semantic versioning:
- **Major versions** (v1, v2) - Breaking changes
- **Minor versions** (v1.1, v1.2) - New features, backward compatible
- **Patch versions** (v1.1.1) - Bug fixes

Current version: **v1.0.0**

The API version is included in the URL path (`/api/v1/`) and can be checked via the `/api/version` endpoint.

## 📈 Migration Guides

When upgrading between versions, refer to:
1. **CHANGELOG.md** - Detailed change list
2. **Migration guides** - Step-by-step upgrade instructions
3. **Breaking changes** - Compatibility notices
4. **Deprecation notices** - Features being phased out

---

**🎉 Ready to integrate!** Start with the interactive documentation at `http://authos.test/docs/` or import the Postman collection to begin testing.