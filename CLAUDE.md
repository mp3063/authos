# CLAUDE.md - Laravel 12 Auth Service

## Project Overview
Enterprise authentication service - Auth0/Okta alternative with Filament 4 admin, OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.

**Status**: Production-Ready ✅
- **~1,280 test methods**, **154 API endpoints**, **12 Filament resources**
- Multi-tenant with organization isolation
- Complete OAuth 2.0 + PKCE, OIDC, SAML 2.0
- 5 social providers (Google, GitHub, Facebook, Twitter, LinkedIn)
- LDAP/AD integration
- Enterprise features: branding, custom domains, webhooks, audit/compliance
- Security: OWASP Top 10 compliant, intrusion detection, progressive lockout
- Performance: Multi-layer caching, compression, connection pooling
- Monitoring: Health checks, metrics, error tracking, real-time dashboards

## Technology Stack
- **PHP**: 8.4.13 | **Laravel**: 12.32.5 | **Filament**: 4.0.3
- **Passport**: 13.1 | **Socialite**: 5.23 | **Spatie Permission**: 6.21
- **Database**: PostgreSQL (46 tables) | **Cache**: Redis/Database
- **Testing**: PHPUnit 11.5.42 | **Frontend**: Tailwind CSS 4.0

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
- Admin: http://authos.test/admin (admin@authservice.com / password)
- API: http://authos.test/api/v1

## Development Commands

```bash
# Database
herd php artisan migrate:refresh --seed
herd php artisan passport:keys

# Testing
./run-tests.sh                             # Full suite (~1,280 tests)
./run-tests.sh tests/Unit/                 # Unit tests
./run-tests.sh tests/Integration/OAuth/    # OAuth integration
herd composer test:coverage                # With coverage report

# Code Quality
herd composer quality                      # Run all quality checks
herd composer quality:fix                  # Auto-fix issues
herd composer cs:fix                       # Fix code style (Pint)
herd composer analyse                      # PHPStan Level 5
herd composer security:check               # Security audit

# Performance & Monitoring
herd php artisan cache:warm                # Warm caches
herd php artisan monitor:health            # Health check
```

## Core Architecture

### Multi-Tenant Security
- Organization-based isolation (users only see their org data)
- Super Admin has cross-organization access
- All Filament resources properly scoped

### OAuth 2.0 Compliance
- Authorization code flow (RFC 6749)
- PKCE support (S256 + plain)
- Refresh token rotation
- Token introspection (RFC 7662)
- OpenID Connect Discovery

### Key Models
- **User** - MFA, organization relationships, social accounts
- **Organization** - Multi-tenant settings, security policies
- **Application** - OAuth clients with auto-generated credentials
- **AuthenticationLog** - Comprehensive audit trail
- **SSOConfiguration** - OIDC/SAML 2.0 per organization
- **LdapConfiguration** - LDAP/AD integration
- **Webhook** - Event-driven integrations with retry logic
- **CustomDomain** - Domain verification and SSL

## Admin Panel (Filament 4)

### Resources (12)
1. **Users** - MFA controls, bulk operations, session management
2. **Organizations** - Settings, security policies, branding
3. **Applications** - OAuth client management, credentials
4. **Roles** - Custom role management (RBAC)
5. **Permissions** - Permission management (RBAC)
6. **Authentication Logs** - Security monitoring, audit trail
7. **Social Accounts** - Provider management, connections
8. **Invitations** - User invitation workflow
9. **LDAP Configurations** - AD integration settings
10. **Custom Domains** - Domain verification, DNS records
11. **Webhooks** - Event subscriptions, configuration
12. **Webhook Deliveries** - Delivery logs, retry management

### Dashboard Widgets (13)
- **System Health** - Real-time health status
- **Real-Time Metrics** - Auto-refresh metrics (30s intervals)
- **Auth Stats Overview** - Authentication statistics
- **OAuth Flow Monitor** - Token generation trends
- **Security Monitoring** - Security alerts & incidents
- **Error Trends** - 7-day error analysis
- **Login Activity Chart** - Login patterns visualization
- **User Activity** - Active users tracking
- **Webhook Activity Chart** - Webhook delivery stats
- **Recent Authentication Logs** - Latest auth events
- **Pending Invitations** - Invitation queue
- **Organization Overview** - Org statistics
- **Application Access Matrix** - OAuth app permissions

## API Endpoints (154 Total)

### Core Categories
- **Auth** (12) - register, login, logout, MFA, social (5 providers)
- **Users** (15) - CRUD, roles, sessions, applications, bulk operations
- **Applications** (13) - OAuth clients, credentials, analytics, tokens
- **Organizations** (20+) - CRUD, settings, custom roles, invitations, metrics
- **Profile** (9) - User profile, avatar, preferences, security
- **MFA** (10) - TOTP setup/verify, recovery codes
- **SSO** (15+) - OIDC/SAML login, sessions, configurations
- **Enterprise** (15+) - LDAP, Branding, Domains, Audit/Compliance
- **OAuth** (10) - authorize, token, introspect, userinfo, jwks, revoke
- **Webhooks** (10+) - CRUD, test, deliveries, events
- **Bulk Operations** (8+) - Import/export users, migration tools
- **Monitoring** (20+) - Health checks, Metrics, Errors

### Well-Known Endpoints
- `GET /.well-known/openid-configuration` - OIDC Discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set

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

# Social Providers (configure as needed)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=
TWITTER_CLIENT_ID=
TWITTER_CLIENT_SECRET=
LINKEDIN_CLIENT_ID=
LINKEDIN_CLIENT_SECRET=

# Security
MFA_ISSUER="${APP_NAME}"
RATE_LIMIT_API=100
RATE_LIMIT_AUTH=10
```

## Features Overview

### Authentication & Authorization
- Multi-factor authentication (TOTP)
- Social login (5 providers)
- SSO (OIDC, SAML 2.0)
- LDAP/Active Directory integration
- OAuth 2.0 authorization server
- Session management
- Account lockout policies

### Enterprise Features
- Custom branding (logo, colors, CSS)
- Custom domains with DNS verification
- Audit log export (CSV, JSON, Excel)
- Compliance support (SOC2, ISO 27001, GDPR)
- Webhook system (44 event types)
- Bulk user operations
- Migration tools (Auth0, Okta)

### Security Features
- Multi-tenant isolation
- Enhanced security headers (CSP, HSTS, Permissions-Policy)
- Intrusion detection (brute force, SQL injection, XSS)
- Progressive account lockout (5min → 24hrs)
- Automatic IP blocking
- Security incident management
- Rate limiting (role-based)
- Comprehensive audit logging
- OWASP Top 10 (2021) compliant

### Performance Features
- Multi-layer caching
- Response compression
- Connection pooling
- Optimized database queries
- Eager loading strategies

### Monitoring Features
- Health check endpoints
- Real-time metrics
- Error tracking
- Dashboard widgets
- Performance monitoring

## Sample Data

**Organizations:**
- TechCorp Solutions (standard security)
- SecureBank Holdings (high security, MFA required)

**Default Roles:**
- Super Admin - Full system access
- Organization Owner - Full org management
- Organization Admin - User/app management
- User - Basic access

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
- For coverage: `herd composer test:coverage`

## Important Notes

### Development Guidelines
- Always use `herd php` prefix for artisan commands (version mismatch prevention)
- Use specialized subagents when appropriate
- Don't use `--verbose` flag with tests (causes errors)
- For PhpStorm coverage: add `-d memory_limit=1G` to prevent exhaustion

### Laravel Boost Integration
See `.claude/laravel-boost.md` for comprehensive development guidelines:
- Package versions and conventions
- Filament 4 best practices and testing
- Laravel 12 structure and patterns
- Livewire 3 component development
- PHPUnit testing requirements
- Tailwind CSS 4 usage
- Code formatting with Pint

### Memory System
See `.claude/memory/INDEX.md` for documented solutions to common issues:
- Filament 4 breaking changes
- PHP 8.4 type issues
- Tab badge query initialization
