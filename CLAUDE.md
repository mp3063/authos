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

===

<laravel-boost-guidelines>
=== foundation rules ===

# Laravel Boost Guidelines

The Laravel Boost guidelines are specifically curated by Laravel maintainers for this application. These guidelines should be followed closely to enhance the user's satisfaction building Laravel applications.

## Foundational Context
This application is a Laravel application and its main Laravel ecosystems package & versions are below. You are an expert with them all. Ensure you abide by these specific packages & versions.

- php - 8.4.19
- filament/filament (FILAMENT) - v4
- laravel/fortify (FORTIFY) - v1
- laravel/framework (LARAVEL) - v12
- laravel/passport (PASSPORT) - v13
- laravel/prompts (PROMPTS) - v0
- laravel/socialite (SOCIALITE) - v5
- livewire/livewire (LIVEWIRE) - v3
- larastan/larastan (LARASTAN) - v3
- laravel/mcp (MCP) - v0
- laravel/pint (PINT) - v1
- laravel/sail (SAIL) - v1
- phpunit/phpunit (PHPUNIT) - v11
- tailwindcss (TAILWINDCSS) - v4

## Conventions
- You must follow all existing code conventions used in this application. When creating or editing a file, check sibling files for the correct structure, approach, naming.
- Use descriptive names for variables and methods. For example, `isRegisteredForDiscounts`, not `discount()`.
- Check for existing components to reuse before writing a new one.

## Verification Scripts
- Do not create verification scripts or tinker when tests cover that functionality and prove it works. Unit and feature tests are more important.

## Application Structure & Architecture
- Stick to existing directory structure - don't create new base folders without approval.
- Do not change the application's dependencies without approval.

## Frontend Bundling
- If the user doesn't see a frontend change reflected in the UI, it could mean they need to run `npm run build`, `npm run dev`, or `composer run dev`. Ask them.

## Replies
- Be concise in your explanations - focus on what's important rather than explaining obvious details.

## Documentation Files
- You must only create documentation files if explicitly requested by the user.


=== boost rules ===

## Laravel Boost
- Laravel Boost is an MCP server that comes with powerful tools designed specifically for this application. Use them.

## Artisan
- Use the `list-artisan-commands` tool when you need to call an Artisan command to double check the available parameters.

## URLs
- Whenever you share a project URL with the user you should use the `get-absolute-url` tool to ensure you're using the correct scheme, domain / IP, and port.

## Tinker / Debugging
- You should use the `tinker` tool when you need to execute PHP to debug code or query Eloquent models directly.
- Use the `database-query` tool when you only need to read from the database.

## Reading Browser Logs With the `browser-logs` Tool
- You can read browser logs, errors, and exceptions using the `browser-logs` tool from Boost.
- Only recent browser logs will be useful - ignore old logs.

## Searching Documentation (Critically Important)
- Boost comes with a powerful `search-docs` tool you should use before any other approaches. This tool automatically passes a list of installed packages and their versions to the remote Boost API, so it returns only version-specific documentation specific for the user's circumstance. You should pass an array of packages to filter on if you know you need docs for particular packages.
- The 'search-docs' tool is perfect for all Laravel related packages, including Laravel, Inertia, Livewire, Filament, Tailwind, Pest, Nova, Nightwatch, etc.
- You must use this tool to search for Laravel-ecosystem documentation before falling back to other approaches.
- Search the documentation before making code changes to ensure we are taking the correct approach.
- Use multiple, broad, simple, topic based queries to start. For example: `['rate limiting', 'routing rate limiting', 'routing']`.
- Do not add package names to queries - package information is already shared. For example, use `test resource table`, not `filament 4 test resource table`.

### Available Search Syntax
- You can and should pass multiple queries at once. The most relevant results will be returned first.

1. Simple Word Searches with auto-stemming - query=authentication - finds 'authenticate' and 'auth'
2. Multiple Words (AND Logic) - query=rate limit - finds knowledge containing both "rate" AND "limit"
3. Quoted Phrases (Exact Position) - query="infinite scroll" - Words must be adjacent and in that order
4. Mixed Queries - query=middleware "rate limit" - "middleware" AND exact phrase "rate limit"
5. Multiple Queries - queries=["authentication", "middleware"] - ANY of these terms


=== php rules ===

## PHP

- Always use curly braces for control structures, even if it has one line.

### Constructors
- Use PHP 8 constructor property promotion in `__construct()`.
    - <code-snippet>public function __construct(public GitHub $github) { }</code-snippet>
- Do not allow empty `__construct()` methods with zero parameters.

### Type Declarations
- Always use explicit return type declarations for methods and functions.
- Use appropriate PHP type hints for method parameters.

<code-snippet name="Explicit Return Types and Method Params" lang="php">
protected function isAccessible(User $user, ?string $path = null): bool
{
    ...
}
</code-snippet>

## Comments
- Prefer PHPDoc blocks over comments. Never use comments within the code itself unless there is something _very_ complex going on.

## PHPDoc Blocks
- Add useful array shape type definitions for arrays when appropriate.

## Enums
- Typically, keys in an Enum should be TitleCase. For example: `FavoritePerson`, `BestLake`, `Monthly`.


=== laravel/core rules ===

## Do Things the Laravel Way

- Use `php artisan make:` commands to create new files (i.e. migrations, controllers, models, etc.). You can list available Artisan commands using the `list-artisan-commands` tool.
- If you're creating a generic PHP class, use `artisan make:class`.
- Pass `--no-interaction` to all Artisan commands to ensure they work without user input. You should also pass the correct `--options` to ensure correct behavior.

### Database
- Always use proper Eloquent relationship methods with return type hints. Prefer relationship methods over raw queries or manual joins.
- Use Eloquent models and relationships before suggesting raw database queries
- Avoid `DB::`; prefer `Model::query()`. Generate code that leverages Laravel's ORM capabilities rather than bypassing them.
- Generate code that prevents N+1 query problems by using eager loading.
- Use Laravel's query builder for very complex database operations.

### Model Creation
- When creating new models, create useful factories and seeders for them too. Ask the user if they need any other things, using `list-artisan-commands` to check the available options to `php artisan make:model`.

### APIs & Eloquent Resources
- For APIs, default to using Eloquent API Resources and API versioning unless existing API routes do not, then you should follow existing application convention.

### Controllers & Validation
- Always create Form Request classes for validation rather than inline validation in controllers. Include both validation rules and custom error messages.
- Check sibling Form Requests to see if the application uses array or string based validation rules.

### Queues
- Use queued jobs for time-consuming operations with the `ShouldQueue` interface.

### Authentication & Authorization
- Use Laravel's built-in authentication and authorization features (gates, policies, Sanctum, etc.).

### URL Generation
- When generating links to other pages, prefer named routes and the `route()` function.

### Configuration
- Use environment variables only in configuration files - never use the `env()` function directly outside of config files. Always use `config('app.name')`, not `env('APP_NAME')`.

### Testing
- When creating models for tests, use the factories for the models. Check if the factory has custom states that can be used before manually setting up the model.
- Faker: Use methods such as `$this->faker->word()` or `fake()->randomDigit()`. Follow existing conventions whether to use `$this->faker` or `fake()`.
- When creating tests, make use of `php artisan make:test [options] <name>` to create a feature test, and pass `--unit` to create a unit test. Most tests should be feature tests.

### Vite Error
- If you receive an "Illuminate\Foundation\ViteException: Unable to locate file in Vite manifest" error, you can run `npm run build` or ask the user to run `npm run dev` or `composer run dev`.


=== laravel/v12 rules ===

## Laravel 12

- Use the `search-docs` tool to get version specific documentation.
- Since Laravel 11, Laravel has a new streamlined file structure which this project uses.

### Laravel 12 Structure
- No middleware files in `app/Http/Middleware/`.
- `bootstrap/app.php` is the file to register middleware, exceptions, and routing files.
- `bootstrap/providers.php` contains application specific service providers.
- **No app\Console\Kernel.php** - use `bootstrap/app.php` or `routes/console.php` for console configuration.
- **Commands auto-register** - files in `app/Console/Commands/` are automatically available and do not require manual registration.

### Database
- When modifying a column, the migration must include all of the attributes that were previously defined on the column. Otherwise, they will be dropped and lost.
- Laravel 11 allows limiting eagerly loaded records natively, without external packages: `$query->latest()->limit(10);`.

### Models
- Casts can and likely should be set in a `casts()` method on a model rather than the `$casts` property. Follow existing conventions from other models.


=== livewire/core rules ===

## Livewire Core
- Use the `search-docs` tool to find exact version specific documentation for how to write Livewire & Livewire tests.
- Use the `php artisan make:livewire [Posts\CreatePost]` artisan command to create new components
- State should live on the server, with the UI reflecting it.
- All Livewire requests hit the Laravel backend, they're like regular HTTP requests. Always validate form data, and run authorization checks in Livewire actions.

## Livewire Best Practices
- Livewire components require a single root element.
- Use `wire:loading` and `wire:dirty` for delightful loading states.
- Add `wire:key` in loops:

    ```blade
    @foreach ($items as $item)
        <div wire:key="item-{{ $item->id }}">
            {{ $item->name }}
        </div>
    @endforeach
    ```

- Prefer lifecycle hooks like `mount()`, `updatedFoo()` for initialization and reactive side effects:

<code-snippet name="Lifecycle hook examples" lang="php">
    public function mount(User $user) { $this->user = $user; }
    public function updatedSearch() { $this->resetPage(); }
</code-snippet>


## Testing Livewire

<code-snippet name="Example Livewire component test" lang="php">
    Livewire::test(Counter::class)
        ->assertSet('count', 0)
        ->call('increment')
        ->assertSet('count', 1)
        ->assertSee(1)
        ->assertStatus(200);
</code-snippet>


    <code-snippet name="Testing a Livewire component exists within a page" lang="php">
        $this->get('/posts/create')
        ->assertSeeLivewire(CreatePost::class);
    </code-snippet>


=== livewire/v3 rules ===

## Livewire 3

### Key Changes From Livewire 2
- These things changed in Livewire 2, but may not have been updated in this application. Verify this application's setup to ensure you conform with application conventions.
    - Use `wire:model.live` for real-time updates, `wire:model` is now deferred by default.
    - Components now use the `App\Livewire` namespace (not `App\Http\Livewire`).
    - Use `$this->dispatch()` to dispatch events (not `emit` or `dispatchBrowserEvent`).
    - Use the `components.layouts.app` view as the typical layout path (not `layouts.app`).

### New Directives
- `wire:show`, `wire:transition`, `wire:cloak`, `wire:offline`, `wire:target` are available for use. Use the documentation to find usage examples.

### Alpine
- Alpine is now included with Livewire, don't manually include Alpine.js.
- Plugins included with Alpine: persist, intersect, collapse, and focus.

### Lifecycle Hooks
- You can listen for `livewire:init` to hook into Livewire initialization, and `fail.status === 419` for the page expiring:

<code-snippet name="livewire:load example" lang="js">
document.addEventListener('livewire:init', function () {
    Livewire.hook('request', ({ fail }) => {
        if (fail && fail.status === 419) {
            alert('Your session expired');
        }
    });

    Livewire.hook('message.failed', (message, component) => {
        console.error(message);
    });
});
</code-snippet>


=== pint/core rules ===

## Laravel Pint Code Formatter

- You must run `vendor/bin/pint --dirty` before finalizing changes to ensure your code matches the project's expected style.
- Do not run `vendor/bin/pint --test`, simply run `vendor/bin/pint` to fix any formatting issues.


=== phpunit/core rules ===

## PHPUnit Core

- This application uses PHPUnit for testing. All tests must be written as PHPUnit classes. Use `php artisan make:test --phpunit <name>` to create a new test.
- If you see a test using "Pest", convert it to PHPUnit.
- Every time a test has been updated, run that singular test.
- When the tests relating to your feature are passing, ask the user if they would like to also run the entire test suite to make sure everything is still passing.
- Tests should test all of the happy paths, failure paths, and weird paths.
- You must not remove any tests or test files from the tests directory without approval. These are not temporary or helper files, these are core to the application.

### Running Tests
- Run the minimal number of tests, using an appropriate filter, before finalizing.
- To run all tests: `php artisan test`.
- To run all tests in a file: `php artisan test tests/Feature/ExampleTest.php`.
- To filter on a particular test name: `php artisan test --filter=testName` (recommended after making a change to a related file).


=== tailwindcss/core rules ===

## Tailwind Core

- Use Tailwind CSS classes to style HTML, check and use existing tailwind conventions within the project before writing your own.
- Offer to extract repeated patterns into components that match the project's conventions (i.e. Blade, JSX, Vue, etc..)
- Think through class placement, order, priority, and defaults - remove redundant classes, add classes to parent or child carefully to limit repetition, group elements logically
- You can use the `search-docs` tool to get exact examples from the official documentation when needed.

### Spacing
- When listing items, use gap utilities for spacing, don't use margins.

    <code-snippet name="Valid Flex Gap Spacing Example" lang="html">
        <div class="flex gap-8">
            <div>Superior</div>
            <div>Michigan</div>
            <div>Erie</div>
        </div>
    </code-snippet>


### Dark Mode
- If existing pages and components support dark mode, new pages and components must support dark mode in a similar way, typically using `dark:`.


=== tailwindcss/v4 rules ===

## Tailwind 4

- Always use Tailwind CSS v4 - do not use the deprecated utilities.
- `corePlugins` is not supported in Tailwind v4.
- In Tailwind v4, configuration is CSS-first using the `@theme` directive — no separate `tailwind.config.js` file is needed.
<code-snippet name="Extending Theme in CSS" lang="css">
@theme {
  --color-brand: oklch(0.72 0.11 178);
}
</code-snippet>

- In Tailwind v4, you import Tailwind using a regular CSS `@import` statement, not using the `@tailwind` directives used in v3:

<code-snippet name="Tailwind v4 Import Tailwind Diff" lang="diff">
   - @tailwind base;
   - @tailwind components;
   - @tailwind utilities;
   + @import "tailwindcss";
</code-snippet>


### Replaced Utilities
- Tailwind v4 removed deprecated utilities. Do not use the deprecated option - use the replacement.
- Opacity values are still numeric.

| Deprecated |	Replacement |
|------------+--------------|
| bg-opacity-* | bg-black/* |
| text-opacity-* | text-black/* |
| border-opacity-* | border-black/* |
| divide-opacity-* | divide-black/* |
| ring-opacity-* | ring-black/* |
| placeholder-opacity-* | placeholder-black/* |
| flex-shrink-* | shrink-* |
| flex-grow-* | grow-* |
| overflow-ellipsis | text-ellipsis |
| decoration-slice | box-decoration-slice |
| decoration-clone | box-decoration-clone |


=== tests rules ===

## Test Enforcement

- Every change must be programmatically tested. Write a new test or update an existing test, then run the affected tests to make sure they pass.
- Run the minimum number of tests needed to ensure code quality and speed. Use `php artisan test` with a specific filename or filter.


=== laravel/fortify rules ===

## Laravel Fortify

Fortify is a headless authentication backend that provides authentication routes and controllers for Laravel applications.

**Before implementing any authentication features, use the `search-docs` tool to get the latest docs for that specific feature.**

### Configuration & Setup
- Check `config/fortify.php` to see what's enabled. Use `search-docs` for detailed information on specific features.
- Enable features by adding them to the `'features' => []` array: `Features::registration()`, `Features::resetPasswords()`, etc.
- To see the all Fortify registered routes, use the `list-routes` tool with the `only_vendor: true` and `action: "Fortify"` parameters.
- Fortify includes view routes by default (login, register). Set `'views' => false` in the configuration file to disable them if you're handling views yourself.

### Customization
- Views can be customized in `FortifyServiceProvider`'s `boot()` method using `Fortify::loginView()`, `Fortify::registerView()`, etc.
- Customize authentication logic with `Fortify::authenticateUsing()` for custom user retrieval / validation.
- Actions in `app/Actions/Fortify/` handle business logic (user creation, password reset, etc.). They're fully customizable, so you can modify them to change feature behavior.

## Available Features
- `Features::registration()` for user registration.
- `Features::emailVerification()` to verify new user emails.
- `Features::twoFactorAuthentication()` for 2FA with QR codes and recovery codes.
  - Add options: `['confirmPassword' => true, 'confirm' => true]` to require password confirmation and OTP confirmation before enabling 2FA.
- `Features::updateProfileInformation()` to let users update their profile.
- `Features::updatePasswords()` to let users change their passwords.
- `Features::resetPasswords()` for password reset via email.
</laravel-boost-guidelines>
