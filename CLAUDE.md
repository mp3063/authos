# CLAUDE.md - Laravel 13 Auth Service

## Project Overview
Enterprise authentication service - Auth0/Okta alternative with Filament 5 admin, OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.

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
- **PHP**: 8.4.25 | **Laravel**: 13.35.0 | **Filament**: 5.10.0 | **Livewire**: 4.4.7
- **Passport**: 13.9 | **Socialite**: 5.31 | **Spatie Permission**: 8.3
- **Database**: PostgreSQL (46 tables) | **Cache**: Redis/Database
- **Testing**: PHPUnit 13.4 + ParaTest | **Frontend**: Tailwind CSS 4.3, Vite 8

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

## Admin Panel (Filament 5)

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
- **No code comments unless absolutely necessary** (app code, tests, config). Explain *why* in the commit message instead. Only exception: a one-line comment where the code would otherwise be actively misleading. Pass this rule on to subagents that write code.

### Laravel Boost Integration
See `.claude/laravel-boost.md` for comprehensive development guidelines:
- Package versions and conventions
- Filament 5 best practices and testing
- Laravel 13 structure and patterns
- Livewire 4 component development
- PHPUnit testing requirements
- Tailwind CSS 4 usage
- Code formatting with Pint

### Memory System
See `.claude/memory/INDEX.md` for documented solutions to common issues:
- Filament 4 breaking changes
- PHP 8.4 type issues
- Tab badge query initialization

===

<laravel-boost-guidelines>
=== foundation rules ===

# Laravel Boost Guidelines

## Foundational Context

This application is a Laravel application running on PHP 8.4. Always use the APIs that match the installed major version of each package — do not assume a version.

Before relying on a package's API, confirm its installed version:
- PHP packages: run `composer show --direct` to list direct dependencies with versions, or `composer show <vendor/package>` for a single package.
- JS packages: check `package.json` for the installed versions.

## Skills Activation

This project has domain-specific skills available in `**/skills/**`. You MUST activate the relevant skill whenever you work in that domain—don't wait until you're stuck.

## Conventions

- You must follow all existing code conventions used in this application. When creating or editing a file, check sibling files for the correct structure, approach, and naming.
- Use descriptive names for variables and methods. For example, `isRegisteredForDiscounts`, not `discount()`.
- Check for existing components to reuse before writing a new one.

## Verification Scripts

- Do not create verification scripts or tinker when tests cover that functionality and prove they work. Unit and feature tests are more important.

## Application Structure & Architecture

- Stick to existing directory structure; don't create new base folders without approval.
- Do not change the application's dependencies without approval.

## Frontend Bundling

- If a frontend change doesn't show in the UI or you get a "Unable to locate file in Vite manifest" error, run `npm run build` or ask the user to run `npm run dev` or `composer run dev`.

## Documentation Files

- You must only create documentation files if explicitly requested by the user.

=== boost rules ===

# Laravel Boost

## Project Rules

- This project contains committed, area-grouped rules in `.ai/rules` when that directory exists, including path-scoped framework guidelines under `.ai/rules/boost`. Before you enter plan mode or create/edit any file, you MUST first: open @.ai/rules/index.md (it maps file globs to rule files), read every rule file whose globs cover the path(s) in scope, and run `grep -rin 'keyword' .ai/rules` to catch what a path match alone misses. Do not write code until you have read and are following every matching rule. If `.ai/rules` does not exist, continue without it.

## Artisan

- Run Artisan commands directly via the command line (e.g., `php artisan route:list`). Use `php artisan list` to discover available commands and `php artisan [command] --help` to check parameters.
- Inspect routes with `php artisan route:list`. Filter with: `--method=GET`, `--name=users`, `--path=api`, `--except-vendor`, `--only-vendor`.
- Read configuration values using dot notation: `php artisan config:show app.name`, `php artisan config:show database.default`. Or read config files directly from the `config/` directory.

## Tinker

- Execute PHP in app context for debugging and testing code. Do not create models without user approval, prefer tests with factories instead. Prefer existing Artisan commands over custom tinker code.
- Always use single quotes to prevent shell expansion: `php artisan tinker --execute 'Your::code();'`
  - Double quotes for PHP strings inside: `php artisan tinker --execute 'User::where("active", true)->count();'`

=== php rules ===

# PHP

- Always use curly braces for control structures, even for single-line bodies.
- Use PHP 8 constructor property promotion: `public function __construct(public GitHub $github) { }`. Do not leave empty zero-parameter `__construct()` methods unless the constructor is private.
- Use explicit return type declarations and type hints for all method parameters: `function isAccessible(User $user, ?string $path = null): bool`
- Follow existing application Enum naming conventions.
- Prefer PHPDoc blocks over inline comments. Only add inline comments for exceptionally complex logic.
- Use array shape type definitions in PHPDoc blocks.

=== deployments rules ===

# Deployment

- Laravel can be deployed using [Laravel Cloud](https://cloud.laravel.com/), which is the fastest way to deploy and scale production Laravel applications.

=== tests rules ===

# Test Enforcement

- Add or update tests for behavior and logic changes when a test provides meaningful regression coverage.
- Pure copy, styling, and layout-only changes do not require new or updated tests.
- When test coverage applies, run the affected tests and ensure they pass.
- Test the changed behavior and its important failure modes, but do not add tests beyond them.
- Read the `testing-best-practices` skill before writing tests.

=== laravel/core rules ===

# Do Things the Laravel Way

- Use `php artisan make:` commands to create new files (i.e. migrations, controllers, models, etc.). You can list available Artisan commands using `php artisan list` and check their parameters with `php artisan [command] --help`.
- If you're creating a generic PHP class, use `php artisan make:class`.
- Pass `--no-interaction` to all Artisan commands to ensure they work without user input. You should also pass the correct `--options` to ensure correct behavior.

### Model Creation

- When creating new models, create useful factories and seeders for them too. Ask the user if they need any other things, using `php artisan make:model --help` to check the available options.

## APIs & Eloquent Resources

- For APIs, default to using Eloquent API Resources and API versioning unless existing API routes do not, then you should follow existing application convention.

## URL Generation

- When generating links to other pages, prefer named routes and the `route()` function.

## Testing

- When creating models for tests, use the factories for the models. Check if the factory has custom states that can be used before manually setting up the model.
- Faker: Use methods such as `$this->faker->word()` or `fake()->randomDigit()`. Follow existing conventions whether to use `$this->faker` or `fake()`.
- When creating tests, make use of `php artisan make:test [options] {name}` to create a feature test, and pass `--unit` to create a unit test. Most tests should be feature tests.

=== pint/core rules ===

# Laravel Pint Code Formatter

- If you have modified any PHP files, you must run `vendor/bin/pint --dirty --format agent` before finalizing changes to ensure your code matches the project's expected style.
- Do not run `vendor/bin/pint --test --format agent`, simply run `vendor/bin/pint --format agent` to fix any formatting issues.

=== phpunit/core rules ===

# PHPUnit

- This project uses PHPUnit. Create tests with `php artisan make:test --phpunit {name}`.
- Do not include the test suite directory in `{name}`. Use `SomeFeatureTest`, not `Feature/SomeFeatureTest`.
- Read the `testing-best-practices` skill for guidance on coverage, naming, structure, dependency isolation, and review.

## Running Tests

- Run the narrowest set of tests that covers the change. Pass a file path or `--filter=testName` to `php artisan test --compact`.
- Rerun a test after each change to it.
- Run `vendor/bin/phpunit` to call the test runner directly. It accepts the same file path and `--filter=testName` arguments.

</laravel-boost-guidelines>
