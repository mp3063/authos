# CLAUDE.md - Laravel 12 Auth Service Documentation

## Project Overview
Laravel 12 enterprise authentication service - Auth0 alternative with Filament 4 admin, OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.

**Status**: Production-Ready ✅
- 933+ test methods, 144 REST endpoints
- Multi-tenant with organization isolation
- Complete OAuth 2.0 + PKCE, OIDC, SAML 2.0
- 5 social providers, LDAP/AD integration
- Enterprise features: branding, domains, audit, compliance

## Technology Stack
- **PHP**: 8.4.13 | **Laravel**: 12.25.0 | **Filament**: 4.x
- **Passport**: 13.1 | **Socialite**: 5.23 | **Spatie Permission**: 6.21
- **Database**: PostgreSQL | **Cache**: Redis/Database
- **Testing**: PHPUnit 11.5.34 | **Frontend**: Tailwind CSS 4.0

## Quick Start

```bash
# Install
composer install && npm install
cp .env.example .env
herd php artisan key:generate

# Setup database
herd php artisan migrate --seed
herd php artisan passport:keys
herd php artisan passport:install

# Start
herd start                    # http://authos.test
```

**Access:**
- Admin: http://authos.test/admin (admin@authservice.com / password123)
- API: http://authos.test/api/v1

## Development Commands

```bash
# Database
herd php artisan migrate:refresh --seed
herd php artisan passport:keys

# Testing (use wrapper to prevent hang)
./run-tests.sh                             # Full suite
./run-tests.sh tests/Unit/                 # Unit tests
herd php artisan test --filter=testName    # Specific test

# Coverage
herd coverage ./vendor/bin/phpunit --coverage-text
```

## Core Architecture

### Multi-Tenant Security
- Organization-based isolation (users only see their org data)
- Super Admin has cross-organization access
- All Filament resources properly scoped

### OAuth 2.0 & Security
- Complete authorization code flow (RFC 6749)
- PKCE support (S256 + plain)
- Refresh token rotation
- Token introspection (RFC 7662)
- Unified API response format across all endpoints

### Key Models
- **User** - MFA, organization relationships, social accounts
- **Organization** - Multi-tenant settings, security policies
- **Application** - OAuth clients with auto-generated credentials
- **AuthenticationLog** - Comprehensive audit trail
- **SSOConfiguration** - OIDC/SAML 2.0 per organization
- **LdapConfiguration** - LDAP/AD integration

### Database (30 Tables)
- Core: users, organizations, applications, authentication_logs
- OAuth: oauth_* (5 tables for Passport)
- RBAC: roles, permissions, custom_roles
- SSO: sso_configurations, sso_sessions, social_accounts
- Enterprise: ldap_configurations, custom_domains, organization_branding, audit_exports

## Admin Panel (Filament 4)

**10 Resources:**
1. Users - MFA controls, bulk operations
2. Organizations - Settings, security policies
3. Applications - OAuth client management
4. Roles/Permissions - RBAC
5. Authentication Logs - Security monitoring
6. Social Accounts - Provider management
7. Invitations - User workflow
8. LDAP Configuration - AD integration
9. Custom Domains - Domain verification

## API Endpoints (144 Total)

### Core Categories
- **Auth** (12) - register, login, logout, MFA, social (5 providers)
- **Users** (15) - CRUD, roles, sessions, applications, bulk ops
- **Applications** (13) - OAuth clients, credentials, analytics, tokens
- **Organizations** (36) - CRUD, settings, custom roles, invitations, metrics, reports
- **Profile** (9) - User profile, avatar, preferences, security
- **MFA** (10) - TOTP setup/verify, recovery codes
- **SSO** (19) - OIDC/SAML login, sessions, configurations
- **Enterprise** (19) - LDAP (4), Branding (4), Domains (4), Audit/Compliance (7)
- **OAuth** (10) - authorize, token, introspect, userinfo, jwks, revoke
- **System** - Health, cache, config, monitoring

**Well-Known:**
- `GET /.well-known/openid-configuration` - OIDC Discovery

## Environment Configuration

```bash
# Core
APP_NAME=AuthOS
DB_CONNECTION=pgsql
CACHE_STORE=database
QUEUE_CONNECTION=database

# Passport (auto-generated)
PASSPORT_PERSONAL_ACCESS_CLIENT_ID=
PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET=

# Social Providers (5 providers)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
# + GitHub, Facebook, Twitter, LinkedIn

# Security
MFA_ISSUER="${APP_NAME}"
RATE_LIMIT_API=100
RATE_LIMIT_AUTH=10
```

## Production Features ✅

### Phase 5 Complete (100%)
- **SSO**: OIDC + SAML 2.0 (28/28 tests passing)
- **Social Auth**: 5 providers (9/9 tests passing)
- **LDAP/AD**: Integration (9/9 tests passing)
- **Enterprise Branding**: Logo, colors, CSS (13/13 tests passing)
- **Custom Domains**: DNS verification (11/11 tests passing)
- **Audit Export**: CSV, JSON, Excel (10/10 tests passing)
- **Compliance**: SOC2, ISO 27001, GDPR (8/8 tests passing)

**Total: 94/94 enterprise tests passing (100%)**

## Test Coverage
- **Total**: 933+ test methods across 60 classes
- **Categories**: Unit (40+), Feature (890+), Integration (10+)
- **Infrastructure**: PHPUnit 11.5, PHP 8 attributes, memory-optimized
- **Execution**: Use `./run-tests.sh` to prevent timeout issues

## Sample Data
**Organizations:**
- TechCorp Solutions (standard security)
- SecureBank Holdings (high security, MFA required)

**Roles:**
- Super Admin - Full system access
- Organization Owner - Full org management
- Organization Admin - User/app management
- User - Basic access

## Security Features
- Multi-tenant isolation
- OAuth 2.0/OIDC compliance
- Social authentication (5 providers)
- MFA with TOTP + recovery codes
- Security headers (HSTS, CSP, XSS)
- Rate limiting (role-based)
- Comprehensive audit logging

## Troubleshooting

**Common Fixes:**
```bash
herd restart                              # Admin 500 errors
herd php artisan passport:keys --force    # Missing OAuth keys
herd php artisan migrate:fresh --seed     # Database issues
herd php artisan config:clear             # Config cache issues
```

**Test Execution:**
- PHPUnit may hang after completion - use `./run-tests.sh` wrapper
- Use `Ctrl+C` after seeing test results if needed
- For coverage: `herd coverage ./vendor/bin/phpunit --coverage-text`

## Important Notes
- Use specialized subagents when appropriate
- Always use `herd php` prefix for artisan commands (version mismatch)
- No backward compatibility code needed (no production deployment yet)
- Don't use `--verbose` flag with tests (causes error)
- For PhpStorm coverage: add `-d memory_limit=1G` to prevent exhaustion

## Laravel Boost Guidelines
**See `.claude/laravel-boost.md` for comprehensive development guidelines including:**
- Package versions and conventions
- Filament 4 best practices and testing
- Laravel 12 structure and patterns
- Livewire 3 component development
- PHPUnit testing requirements
- Tailwind CSS 4 usage
- Code formatting with Pint
