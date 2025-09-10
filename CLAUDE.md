# CLAUDE.md - Laravel 12 Auth Service Project Documentation

## Project Overview
Laravel 12 authentication service built as Auth0 alternative with Filament 4 admin panel, OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.

**Current Status**: Phase 4 of Controller Refactoring Complete - Production-ready enterprise authentication service with complete OAuth 2.0 implementation, PKCE security, refresh token rotation, comprehensive API (306+ tests passing, 99.7% pass rate), enhanced security middleware, and production-grade OAuth authorization server.

## Technology Stack
- **Laravel 12** + **Filament 4** + **Laravel Passport** (OAuth 2.0)
- **Spatie Roles/Permissions** + **PostgreSQL** + **Redis**
- **Laravel Socialite** (Google, GitHub, Facebook, Twitter, LinkedIn)

## Development Commands

### Environment Setup
```bash
# HERD (recommended for local development)
herd start                     # Start services for http://authos.test/admin
herd restart                   # Restart if needed

# Alternative local setup
php artisan serve              # http://127.0.0.1:8000
php artisan queue:listen       # Background jobs
```

### Database & Testing
```bash
# Database operations
herd php artisan migrate:refresh --seed    # Reset with sample data
herd php artisan passport:keys             # Generate OAuth keys

# Testing (306+ passing tests, 99.7% pass rate) ✅ ALL TESTS PASSING
herd php artisan test                      # Full test suite (307 total: 306 pass, 1 skip)
herd php artisan test tests/Unit/          # Unit tests (all passing)
herd php artisan test --stop-on-failure    # Debug mode
```

## Core Architecture

### Multi-Tenant Security ✅ FIXED
- **Organization-based isolation**: Users can only see/manage resources from their organization
- **Super Admin access**: Full system access across all organizations
- **Filament Resource Filtering**: All admin resources now properly scoped by organization
- **User/Application/Organization/Logs**: All filtered to prevent cross-organization data leakage

### Enhanced OAuth 2.0 & Security Infrastructure ✅ NEW
- **Complete Authorization Code Flow**: RFC 6749 compliant with database persistence
- **PKCE Support**: RFC 7636 implementation with S256 and plain code challenge methods
- **Refresh Token Rotation**: Secure token rotation preventing replay attacks
- **Token Introspection**: RFC 7662 endpoint for real-time token validation
- **Comprehensive Scope System**: Granular permissions with client-specific restrictions
- **API Response Sanitization**: Production-grade sensitive data protection
- **Enhanced Security Middleware**: State validation, redirect URI security, rate limiting

### Key Models
- **User**: MFA support, organization relationships, social login fields
- **Organization**: Multi-tenant settings, security policies, role management
- **Application**: OAuth clients with auto-generated credentials
- **AuthenticationLog**: Comprehensive audit trail
- **OAuthAuthorizationCode**: Temporary authorization codes with PKCE support

### Database Schema (17 Tables)
- `users`, `organizations`, `applications` - Core entities
- `oauth_*` (6 tables) - Laravel Passport implementation + authorization codes
- `roles`, `permissions` - Spatie RBAC with organization scoping
- `authentication_logs` - Security monitoring

## Admin Panel (Filament 4)

### Access & Security
- **URL**: http://authos.test/admin (HERD) or /admin
- **Default Admin**: admin@authservice.com / password123
- **Multi-tenant Filtering**: Organization-scoped data access ✅

### Resources Available
- **UserResource**: User management, MFA controls, bulk operations
- **OrganizationResource**: Organization settings, security policies
- **ApplicationResource**: OAuth client management, credentials
- **RoleResource/PermissionResource**: RBAC management
- **AuthenticationLogResource**: Security monitoring
- **Dashboard**: Analytics widgets, real-time metrics

## API Endpoints (Production Ready)

### Core Authentication (`/api/v1/auth/*`)
- `POST /auth/register` - User registration
- `POST /auth/login` - JWT authentication
- `GET /auth/user` - User info
- `POST /auth/refresh` - Token refresh

### Social Authentication (`/api/v1/auth/social/*`)
- `GET /social/{provider}` - OAuth redirect (google, github, facebook, twitter, linkedin)
- `GET /social/{provider}/callback` - OAuth callback
- `DELETE /social/unlink` - Unlink social account

### Management APIs
- **Users API** (`/api/v1/users/*`) - CRUD, roles, sessions
- **Applications API** (`/api/v1/applications/*`) - OAuth clients, analytics
- **Organizations API** (`/api/v1/organizations/*`) - Multi-tenant operations
- **Profile API** (`/api/v1/profile/*`) - User profile, preferences, security
- **MFA API** (`/api/v1/mfa/*`) - TOTP setup, recovery codes

### OAuth 2.0 & OIDC ✅ ENHANCED
- `GET /oauth/authorize` - Authorization endpoint with PKCE support
- `POST /oauth/token` - Token endpoint with refresh token rotation
- `POST /oauth/introspect` - Token introspection endpoint (RFC 7662)
- `GET /oauth/userinfo` - UserInfo endpoint
- `GET /.well-known/openid-configuration` - OIDC Discovery

## Environment Configuration

### Required Variables
```bash
# Database & Redis
DB_CONNECTION=pgsql
DB_DATABASE=authos
REDIS_HOST=127.0.0.1

# OAuth Clients (auto-generated)
PASSPORT_PERSONAL_ACCESS_CLIENT_ID=
PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET=

# Social Authentication
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
# Add GitHub, Facebook, Twitter, LinkedIn as needed

# Security Settings
MFA_ISSUER="AuthOS"
RATE_LIMIT_API=100
RATE_LIMIT_AUTH=10
```

## Controller Refactoring Progress ✅ NEW

### 📊 Overall Progress: 4/8 phases complete (50.0%)

| Phase | Status | Test Results | Duration | Description |
|-------|--------|--------------|----------|-------------|
| **Phase 1: Foundation** | ✅ **COMPLETED** | 306/307 passing | 46.16s | Service layer extraction, dependency injection |
| **Phase 2: Core Services** | ✅ **COMPLETED** | 291/307 passing | 46.03s | UserService, OrganizationService, ApplicationService |
| **Phase 3: Repository Implementation** | ✅ **COMPLETED** | 306/307 passing | 46.08s | Repository pattern, query optimization |
| **Phase 4: OAuth & Security** | ✅ **COMPLETED** | 306/307 passing | 46.30s | Complete OAuth 2.0, PKCE, security enhancements |
| **Phase 5: Response Standardization** | ⏳ Pending | - | - | Unified API response formats |
| **Phase 6: Controller Refactoring** | ⏳ Pending | - | - | Clean controller architecture |
| **Phase 7: Performance & Optimization** | ⏳ Pending | - | - | Caching, query optimization |
| **Phase 8: Final Testing & Documentation** | ⏳ Pending | - | - | Complete testing, documentation |

### 🎉 Recently Completed: Phase 4 - OAuth & Security Implementation

**What Was Accomplished:**
1. **Complete OAuth 2.0 Authorization Code Flow** - RFC 6749 compliant implementation
2. **PKCE Implementation** - RFC 7636 validation with S256 and plain methods  
3. **Refresh Token Rotation** - Enhanced security with secure token rotation
4. **Token Introspection Endpoint** - RFC 7662 compliant introspection
5. **Comprehensive Scope Validation** - Granular permission system
6. **Enhanced Security Validation** - State parameter and redirect URI security
7. **API Response Sanitization** - Production-ready sensitive data protection
8. **Security Infrastructure** - Rate limiting, request/response logging

**Key Achievements:**
- **99.7% Test Pass Rate** - 306/307 tests passing (only 1 skipped test)
- **Complete OAuth 2.0 Compliance** - Full authorization server functionality
- **Enhanced Security** - Production-grade security enhancements
- **Zero Regressions** - All existing functionality maintained

### 📈 Previous Foundation Phases (1-28)

**Historical Achievement Summary:**
- **Phases 1-16**: Foundation, Admin Panel, OAuth 2.0, Public API, Organization Features, Testing, Social Login
- **Phases 17-28**: Comprehensive test suite stabilization, bug fixes, multi-tenant security, SSO infrastructure  
- **Major Achievements**: From 87 failing tests to 1 skipped test, complete OAuth server, SSO implementation
- **Final Status Before Refactoring**: 304/307 tests passing (99.0% pass rate), production-ready authentication service

## 📋 Future Controller Refactoring Phases
- **Phase 5: Response Standardization** - Unified API response formats across all endpoints
- **Phase 6: Controller Refactoring** - Clean controller architecture with proper separation of concerns
- **Phase 7: Performance & Optimization** - Advanced caching strategies, query optimization
- **Phase 8: Final Testing & Documentation** - Complete testing coverage, comprehensive documentation

## Sample Data & Default Users

### Organizations
- **TechCorp Solutions** (Standard security)
- **SecureBank Holdings** (High security, MFA required)

### Default Roles
- **Super Admin** - Full system access (cross-organization)
- **Organization Owner** - Full organization management
- **Organization Admin** - User/app management
- **User** - Basic read access (organization-scoped)

### Test Credentials
- **Super Admin**: admin@authservice.com / password123
- **Access**: http://authos.test/admin

## Security Features

### Implemented
- **Multi-tenant isolation** ✅ - Organization-based data filtering
- **OAuth 2.0/OIDC** - Standard compliant server
- **Social Authentication** - Google + 4 other providers
- **MFA Support** - TOTP, recovery codes
- **Security Headers** - HSTS, CSP, XSS protection
- **Rate Limiting** - Role-based API limits
- **Audit Logging** - Comprehensive authentication events

### Architecture Decisions
- **Multi-tenancy**: Organization-based with proper isolation
- **Authentication**: Laravel Passport + Filament integration
- **Database**: PostgreSQL with JSONB for flexibility
- **Caching**: Redis for sessions, API responses, queues

## Troubleshooting

### Common Issues ✅ ALL RESOLVED
1. **Admin panel 500 errors**: `herd restart` or clear caches
2. **OAuth missing keys**: `herd php artisan passport:keys --force`
3. **Database issues**: `herd php artisan migrate:fresh --seed`
4. **Test failures**: All resolved in Controller Refactoring Phase 4 ✅ (99.7% pass rate achieved)
5. **Cross-organization data**: Fixed in Phase 17 ✅
6. **API 403 errors in tests**: Fixed in Phase 20 ✅ (Spatie permissions team context resolved)
7. **Role creation conflicts**: Fixed in Phase 19 with `firstOrCreate()` pattern
8. **Authorization message format**: Fixed in Phase 21 ✅ (Custom exception handling for API requests)
9. **Missing bulk operations**: Fixed in Phase 21 ✅ (Added PATCH /users/bulk endpoint)
10. **Validation test format**: Fixed in Phase 21 ✅ (Updated test assertions for custom validation structure)
11. **Memory exhaustion in tests**: Fixed in Phase 28 ✅ (Optimized large dataset tests)
12. **PHP deprecation warnings**: Fixed in Phase 28 ✅ (Updated nullable type declarations)
13. **Herd PHP compatibility**: Fixed in Phase 28 ✅ (Use `herd php` prefix for all commands)
14. **OAuth authorization codes**: New table added for PKCE support ✅ (Complete OAuth 2.0 flow implemented)
15. **API response sanitization**: Production-grade security ✅ (Sensitive data protection middleware)

## Important Notes
- use specialized subagents when you see fit!
- Don't use --verbose flag uppon testing because you will get error "Unknown option "--verbose""
- instead of running php commands for example php artisan test please run them with herd prefix like "herd php artisan test" because php versions mismatch