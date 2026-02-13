# CLAUDE.md - Laravel 12 Auth Service

## Project Overview
Enterprise authentication service - Auth0/Okta alternative with Filament 4 admin, OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.

**Status**: In Development (99%+ test pass rate)
- **83 Integration test files**, **475+ test methods**, **~46,500 lines of test code**
- **206 API endpoints**, **12 Filament resources**
- **Test Coverage**: 99%+ pass rate overall (~750 tests)
- **Production-Ready Categories**: Security (100% ✅), SSO (100% ✅), OAuth (100% ✅), Webhooks (100% ✅), Cache (100% ✅), Bulk Operations (100% ✅), Monitoring (100% ✅), Model Lifecycle (100% ✅), Organizations (100% ✅), Users (100% ✅), Applications (100% ✅), Profile/MFA (100% ✅), Jobs (100% ✅), Enterprise (99% ✅)
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


# Testing (Sequential Execution - 100% Reliable)
./run-tests.sh                             # All tests (sequential, timeout protected)
./run-tests.sh tests/Unit/                 # Unit tests only (~8 seconds)
./run-tests.sh tests/Integration/OAuth/    # OAuth integration tests
herd composer test                         # All tests via composer
herd composer test:unit                    # Unit tests only
herd composer test:feature                 # Feature tests only
herd composer test:coverage                # With coverage report
herd php artisan test                      # Direct PHPUnit execution

# Test by category (Integration)
herd php artisan test tests/Integration/                   # All integration tests
herd php artisan test tests/Integration/Security/          # Security tests (100% ✅)
herd php artisan test tests/Integration/SSO/               # SSO tests (100% ✅)
herd php artisan test tests/Integration/OAuth/             # OAuth tests (100% ✅)
herd php artisan test tests/Integration/Webhooks/          # Webhook tests (100% ✅)
herd php artisan test tests/Integration/Cache/             # Cache tests (100% ✅)
herd php artisan test tests/Integration/BulkOperations/    # Bulk ops tests (100% ✅)
herd php artisan test tests/Integration/Monitoring/        # Monitoring tests (100% ✅)
herd php artisan test tests/Integration/Models/            # Model lifecycle (100% ✅)
herd php artisan test tests/Integration/Organizations/     # Organization tests (100% ✅)
herd php artisan test tests/Integration/Users/             # User tests (100% ✅)
herd php artisan test tests/Integration/Applications/      # Application tests (100% ✅)
herd php artisan test tests/Integration/Profile/           # Profile/MFA tests (100% ✅)
herd php artisan test tests/Integration/Jobs/              # Job tests (100% ✅)
herd php artisan test tests/Integration/Enterprise/        # Enterprise tests (99% ✅)

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

## Test Suite Architecture

### Overview
- **83 Integration test files** across 19 categories
- **475+ test methods** with **~46,500 lines** of test code
- **99%+ overall pass rate** (~750 tests passing)
- **14 production-ready categories** at 100% pass rate
- **Average execution time**: ~45-60 seconds (full suite)

### Test Organization

```
tests/Integration/
├── Security/          (5 files, 99 tests, 100% ✅)
│   ├── IntrusionDetectionTest.php       - Brute force, SQL injection, XSS detection
│   ├── ProgressiveLockoutTest.php       - Account lockout policies (5min → 24hrs)
│   ├── IpBlockingTest.php               - Automatic IP blocking and unblocking
│   ├── SecurityHeadersTest.php          - CSP, HSTS, Permissions-Policy
│   └── OrganizationBoundaryTest.php     - Multi-tenant isolation enforcement
│
├── SSO/               (5 files, 45 tests, 100% ✅)
│   ├── SsoOidcFlowTest.php              - OpenID Connect authentication
│   ├── SsoSamlFlowTest.php              - SAML 2.0 authentication
│   ├── SsoTokenRefreshTest.php          - Token refresh mechanisms
│   ├── SsoSynchronizedLogoutTest.php    - Multi-session logout
│   └── EnhancedOidcFlowTest.php         - Advanced OIDC scenarios
│
├── OAuth/             (6 files, 10 tests, 100% ✅)
│   ├── AuthorizationCodeFlowTest.php    - OAuth 2.0 authorization code
│   ├── ClientCredentialsFlowTest.php    - Machine-to-machine auth
│   ├── PasswordGrantFlowTest.php        - Resource owner password
│   ├── TokenManagementTest.php          - Token lifecycle
│   ├── TokenRefreshTest.php             - Refresh token rotation
│   └── OpenIdConnectTest.php            - OIDC integration
│
├── Webhooks/          (4 files, 62 tests, 100% ✅)
│   ├── WebhookDeliveryFlowTest.php      - Webhook delivery lifecycle
│   ├── WebhookRetryFlowTest.php         - Retry logic & exponential backoff
│   ├── WebhookEventDispatchTest.php     - Event dispatching (44 event types)
│   └── WebhookPatternMatchingTest.php   - Event pattern matching
│
├── Cache/             (3 files, 28 tests, 100% ✅)
│   ├── CacheStatsTest.php               - Cache statistics tracking
│   ├── CacheClearTest.php               - Cache invalidation strategies
│   └── ApiCachingTest.php               - API response caching
│
├── BulkOperations/    (2 files, 39 tests, 100% ✅)
│   ├── BulkUserImportTest.php           - CSV/Excel/JSON import
│   └── BulkUserExportTest.php           - CSV/Excel/JSON export
│
├── Monitoring/        (5 files, 38 tests, 100% ✅)
│   ├── HealthCheckTest.php              - Health check endpoints
│   ├── MetricsCollectionTest.php        - Metrics gathering
│   ├── PerformanceMetricsTest.php       - Performance tracking
│   ├── ErrorTrackingTest.php            - Error logging & tracking
│   └── CustomMetricsTest.php            - Custom metric definitions
│
├── Models/            (3 files, 40 tests, 100% ✅)
│   ├── ApplicationLifecycleTest.php     - Application model lifecycle
│   ├── SsoSessionLifecycleTest.php      - SSO session lifecycle
│   └── CacheInvalidationTest.php        - Model-triggered cache clearing
│
├── Profile/           (3 files, 38 tests, 100% ✅)
│   ├── ProfileManagementTest.php        - Profile updates, avatar
│   ├── MfaManagementTest.php            - TOTP setup, recovery codes
│   └── SocialAccountsTest.php           - Social account linking
│
├── Applications/      (4 files, 27 tests, 100% ✅)
│   ├── ApplicationCrudTest.php          - OAuth client management
│   ├── ApplicationTokensTest.php        - Token generation
│   ├── ApplicationAnalyticsTest.php     - Usage analytics
│   └── ApplicationUsersTest.php         - User permissions
│
├── Jobs/              (8 files, 50 tests, 100% ✅)
│   ├── DeliverWebhookJobTest.php        - Webhook delivery job
│   ├── ProcessBulkImportJobTest.php     - Bulk import processing
│   ├── ProcessBulkExportJobTest.php     - Bulk export processing
│   ├── ExportUsersJobTest.php           - User export job
│   ├── ProcessAuditExportJobTest.php    - Audit log export
│   ├── GenerateComplianceReportJobTest.php - Compliance reporting
│   ├── SyncLdapUsersJobTest.php         - LDAP synchronization
│   └── ProcessAuth0MigrationJobTest.php - Auth0 migration
│
├── Organizations/     (8 files, 102 tests, 100% ✅)
│   ├── OrganizationCrudTest.php         - CRUD operations
│   ├── OrganizationSettingsTest.php     - Organization settings
│   ├── OrganizationUsersTest.php        - User management
│   ├── OrganizationAnalyticsTest.php    - Analytics & reporting
│   ├── OrganizationInvitationsTest.php  - User invitations
│   ├── OrganizationBulkOpsTest.php      - Bulk operations
│   ├── OrganizationReportsTest.php      - Reporting
│   └── CustomRolesTest.php              - Custom role management
│
├── Users/             (4 files, 53 tests, 100% ✅)
│   ├── UserCrudTest.php                 - CRUD operations
│   ├── UserProfileTest.php              - Profile management
│   ├── UserSessionsTest.php             - Session management
│   └── UserApplicationsTest.php         - Application access
│
├── Enterprise/        (5 files, 88 tests, 99% ✅)
│   ├── LdapAuthenticationTest.php       - LDAP/AD integration
│   ├── BrandingTest.php                 - Custom branding
│   ├── DomainVerificationTest.php       - DNS verification
│   ├── AuditExportTest.php              - Audit log export
│   └── ComplianceReportTest.php         - Compliance reporting
│
└── EndToEnd/          (15 files, comprehensive E2E flows)
    ├── BasicE2EWorkflowTest.php         - Basic user workflows
    ├── AuthenticationFlowsTest.php      - Auth flows
    ├── OAuthFlowsTest.php               - OAuth flows
    ├── SocialAuthFlowsTest.php          - Social auth
    ├── MfaFlowsTest.php                 - MFA workflows
    ├── SsoFlowsTest.php                 - SSO workflows
    ├── ApplicationFlowsTest.php         - Application workflows
    ├── OrganizationFlowsTest.php        - Organization workflows
    ├── AdminPanelFlowsTest.php          - Admin panel
    ├── ApiIntegrationFlowsTest.php      - API integration
    ├── OAuthSecurityFlowsTest.php       - OAuth security
    ├── SocialAuthMfaFlowsTest.php       - Social + MFA
    ├── SecurityComplianceTest.php       - Security compliance
    ├── CompleteUserJourneyTest.php      - End-to-end user journey
    └── EndToEndTestCase.php             - Base test case
```

### Running Tests

**All Integration Tests:**
```bash
herd php artisan test tests/Integration/
./run-tests.sh tests/Integration/
```

**By Category (All Production-Ready):**
```bash
herd php artisan test tests/Integration/Security/         # 5 files, 99 tests
herd php artisan test tests/Integration/SSO/              # 5 files, 45 tests
herd php artisan test tests/Integration/OAuth/            # 6 files, 10 tests
herd php artisan test tests/Integration/Webhooks/         # 4 files, 62 tests
herd php artisan test tests/Integration/Cache/            # 3 files, 28 tests
herd php artisan test tests/Integration/BulkOperations/   # 2 files, 39 tests
herd php artisan test tests/Integration/Monitoring/       # 5 files, 38 tests
herd php artisan test tests/Integration/Models/           # 3 files, 40 tests
herd php artisan test tests/Integration/Organizations/    # 8 files, 102 tests
herd php artisan test tests/Integration/Users/            # 4 files, 53 tests
herd php artisan test tests/Integration/Applications/     # 4 files, 27 tests
herd php artisan test tests/Integration/Profile/          # 3 files, 38 tests
herd php artisan test tests/Integration/Jobs/             # 8 files, 50 tests
herd php artisan test tests/Integration/Enterprise/       # 5 files, 88 tests
```

**Specific Test File:**
```bash
herd php artisan test tests/Integration/Security/IntrusionDetectionTest.php
herd php artisan test tests/Integration/SSO/SsoOidcFlowTest.php
```

**With Profiling:**
```bash
herd php artisan test tests/Integration/ --profile
```

### Test Categories

**Production-Ready (100% Passing):**

1. **Security (5 files, 99 tests)**
   - OWASP Top 10 (2021) compliance
   - Intrusion detection (brute force, SQL injection, XSS)
   - Progressive lockout (5min → 1hr → 24hrs)
   - Automatic IP blocking
   - Enhanced security headers (CSP, HSTS)
   - Multi-tenant boundary enforcement

2. **SSO & OAuth (11 files, 55 tests)**
   - OpenID Connect (OIDC) flow
   - SAML 2.0 flow
   - Token refresh mechanisms
   - Synchronized logout
   - OAuth 2.0 authorization code flow
   - PKCE support
   - Token introspection

3. **Webhooks (4 files, 62 tests)**
   - Delivery lifecycle
   - Retry logic with exponential backoff
   - Event dispatching (44 event types)
   - Pattern matching
   - Signature verification

4. **Cache (3 files, 28 tests)**
   - Cache statistics
   - Cache invalidation strategies
   - API response caching
   - Multi-layer caching

5. **Bulk Operations (2 files, 39 tests)**
   - CSV/Excel/JSON import
   - CSV/Excel/JSON export
   - Job queue management
   - Progress tracking

6. **Monitoring (5 files, 38 tests)**
   - Health check endpoints
   - Metrics collection
   - Performance tracking
   - Error tracking
   - Custom metrics

7. **Model Lifecycle (3 files, 40 tests)**
   - Application auto-generation
   - SSO session management
   - Cache invalidation observers

8. **Organizations (8 files, 102 tests)**
   - CRUD operations
   - Settings management
   - User management
   - Analytics & reporting
   - Invitations
   - Custom roles

9. **Users (4 files, 53 tests)**
   - CRUD operations
   - Profile management
   - Session management
   - Application access

10. **Applications (4 files, 27 tests)**
    - OAuth client management
    - Token generation
    - Usage analytics
    - User permissions

11. **Profile/MFA (3 files, 38 tests)**
    - Profile updates
    - TOTP setup/verification
    - Recovery codes
    - Social account linking

12. **Jobs (8 files, 50 tests)**
    - Background job testing
    - Queue operations
    - Job retry logic
    - Job failure handling

13. **Enterprise (5 files, 88 tests)**
    - LDAP/AD integration
    - Custom branding
    - Domain verification
    - Audit log export
    - Compliance reporting (SOC2, ISO 27001, GDPR)

### Test Writing Guidelines

**PHP 8 Attributes:**
```php
use PHPUnit\Framework\Attributes\Test;

class MyTest extends IntegrationTestCase
{
    #[Test]
    public function it_performs_action(): void
    {
        // Test implementation
    }
}
```

**Structure:**
```php
#[Test]
public function it_describes_expected_behavior(): void
{
    // ARRANGE - Set up test data
    $user = User::factory()->create();

    // ACT - Perform the action
    $response = $this->actingAs($user)->postJson('/api/v1/endpoint', $data);

    // ASSERT - Verify results
    $response->assertOk();
    $this->assertDatabaseHas('table', ['key' => 'value']);
}
```

**Best Practices:**
- Extend `IntegrationTestCase` for E2E tests
- Use descriptive test method names
- Test complete flows, not implementation details
- Verify HTTP responses AND side effects (DB, cache, logs)
- Use factories for test data
- Follow ARRANGE-ACT-ASSERT structure
- See `tests/_templates/` for examples

**Base Test Classes:**
- `IntegrationTestCase` - Full integration tests with database
- `EndToEndTestCase` - Complete E2E workflows
- `TestCase` - Base Laravel test case

## Admin Panel (Filament 4)

### Resources (16)
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
13. **Security Incidents** - Read-only incident list with severity/type filters, resolve/dismiss actions
14. **Account Lockouts** - Read-only lockout list with unlock action, bulk unlock
15. **IP Blocklist** - Create/delete blocked IPs, unblock/reblock actions, bulk unblock
16. **Failed Login Attempts** - Read-only audit log with time-based tabs

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

**Test Database:**
- All tests use `:memory:` SQLite (automatically cleaned after each test)
- `RefreshDatabase` trait uses transactions for perfect test isolation
- No manual cleanup needed - everything handled by PHPUnit
- If you encounter "no such table" errors, check `.claude/memory/testing/database-migrations-fix.md`

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
