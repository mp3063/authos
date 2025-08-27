# AuthOS API Documentation Files

This directory contains comprehensive API documentation for the AuthOS Laravel 12 authentication service.

## 📁 Files Overview

| File | Description | Usage |
|------|-------------|-------|
| `openapi.yaml` | Complete OpenAPI 3.0 specification | Import into API tools, generate SDKs |
| `postman-collection.json` | Postman collection with examples | Import into Postman for testing |
| `public/docs/index.html` | Interactive Swagger UI documentation | Access at `/docs/` URL |
| `API_DOCUMENTATION.md` | Developer integration guide | Read for implementation guidance |

## 🚀 Quick Access

### View Interactive Documentation
- **Local Development**: http://authos.test/docs/
- **Production**: https://api.authos.dev/docs/

### Import into Tools
- **Postman**: Import `postman-collection.json`
- **Insomnia**: Import `openapi.yaml`
- **Swagger Editor**: Load `openapi.yaml`

## 🔧 SDK Generation

Generate client SDKs using the OpenAPI specification:

```bash
# TypeScript/JavaScript
npx @openapitools/openapi-generator-cli generate -i openapi.yaml -g typescript-axios -o ./sdk/js

# Python
openapi-generator-cli generate -i openapi.yaml -g python -o ./sdk/python

# PHP
openapi-generator-cli generate -i openapi.yaml -g php -o ./sdk/php

# Go
openapi-generator-cli generate -i openapi.yaml -g go -o ./sdk/go
```

## 📋 Features Documented

✅ **Authentication Endpoints** - Registration, login, logout, token management  
✅ **OAuth 2.0 & OpenID Connect** - Full OAuth server implementation  
✅ **User Management** - CRUD operations with role-based access  
✅ **Application Management** - OAuth client management  
✅ **Profile Management** - User profile and preferences  
✅ **MFA Management** - TOTP and recovery codes  
✅ **Organization Management** - Multi-tenant organization features  
✅ **Rate Limiting** - Comprehensive rate limiting documentation  
✅ **Error Handling** - Standardized error responses  
✅ **Security Schemes** - Bearer token authentication  

## 🎯 API Highlights

- **119 Total Endpoints** across 8 main categories
- **OAuth 2.0 Compliant** with PKCE support
- **OpenID Connect** discovery and JWKS endpoints
- **Role-based Rate Limiting** (5x for Super Admin, 3x for Org Admin)
- **Multi-tenant Architecture** with organization isolation
- **Comprehensive MFA** with TOTP and backup codes
- **Real-time Monitoring** with authentication event logging

## 📊 Endpoint Categories

| Category | Endpoints | Auth Required | Rate Limit |
|----------|-----------|---------------|------------|
| Authentication | 6 | Partial | 5-10/hour |
| OAuth 2.0/OIDC | 5 | Partial | 20/min |
| User Management | 8+ | Admin | 200/hour |
| Application Management | 9+ | Admin | 200/hour |
| Profile Management | 7 | User | 1000/hour |
| MFA Management | 6 | User | 20/hour |
| Organization Management | 9+ | Admin | 200/hour |
| System Info | 1 | None | - |

## 🔐 Authentication Methods

1. **User Login** - Email/password authentication
2. **OAuth Authorization Code** - Standard OAuth flow with PKCE
3. **Client Credentials** - Server-to-server authentication
4. **Implicit Grant** - SPA authentication (less secure)

## 📱 Integration Examples

The documentation includes examples for:
- Single Page Applications (React, Vue, Angular)
- Mobile Applications (iOS, Android with PKCE)
- Server-side Applications (Node.js, PHP, Python)
- API-to-API Communication (Client Credentials)

## 🛠️ Development Workflow

1. **Start with Interactive Docs** - Browse `/docs/` to understand API structure
2. **Import Postman Collection** - Test endpoints with real data
3. **Generate SDK** - Create client library for your language
4. **Follow Integration Guide** - Use `API_DOCUMENTATION.md` for implementation
5. **Test Rate Limiting** - Understand limits and implement proper handling

## ⚡ Performance Notes

- **Response Times** - Most endpoints respond within 100-200ms
- **Pagination** - All list endpoints support pagination (default: 15 items/page)
- **Caching** - Redis caching for improved performance
- **Rate Limiting** - Distributed rate limiting with Redis backend

## 🔄 Versioning

- **Current Version**: v1.0.0
- **API Versioning**: URL path versioning (`/api/v1/`)
- **OpenAPI Version**: 3.0.3
- **Backward Compatibility**: Maintained within major versions

---

**Need Help?** 
- 📖 Read the full integration guide: `API_DOCUMENTATION.md`
- 🌐 Try the interactive docs: http://authos.test/docs/
- 📮 Test with Postman: Import `postman-collection.json`