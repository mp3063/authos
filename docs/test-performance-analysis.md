# Test Performance Analysis

**Generated**: 2025-11-06
**Test Suite**: Integration Tests (83 files, 475+ test methods)
**Current Execution Time**: ~196 seconds (~3.27 minutes) sequential
**Target**: <180 seconds (<3 minutes)

## Executive Summary

The integration test suite is well-structured but has several optimization opportunities that could reduce execution time by **30-40%** (60-80 seconds). The main bottlenecks are:

1. **Database-Heavy Tests**: Large bulk operations (1000+ records)
2. **Sleep Calls**: 7+ explicit sleep() calls adding ~7+ seconds
3. **Complex OAuth Flows**: Repeated full authorization flows per test
4. **Heavy Factory Usage**: Creating unnecessary relationships
5. **Sequential Database Operations**: No transaction batching

## Top 20 Slowest Tests

Based on profiling and code analysis:

### Category 1: Database-Heavy Tests (>1 second)

1. **BulkOperationsIntegrationTest::test_large_import_of_users**
   - **Time**: ~1.56s
   - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:26`
   - **Issue**: Creates 1000 users synchronously
   - **Optimization**: Use database transactions, reduce to 100 users, or use in-memory SQLite

2. **BulkOperationsIntegrationTest::test_memory_usage_during_large_operations**
   - **Time**: ~0.78s
   - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:252`
   - **Issue**: Creates 500 users for memory testing
   - **Optimization**: Reduce to 50 users (memory issues show at smaller scales)

3. **BulkOperationsIntegrationTest::test_large_export_of_users**
   - **Time**: ~0.55-0.56s
   - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:67`
   - **Issue**: Creates 1000 users then exports them
   - **Optimization**: Reduce to 100 users, file I/O can be mocked

4. **BulkOperationsIntegrationTest::test_export_with_large_dataset_and_filters**
   - **Time**: ~0.55s
   - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:186`
   - **Issue**: Creates 1000 users (500 verified, 500 unverified)
   - **Optimization**: Reduce to 100 total users

5. **BulkOperationsIntegrationTest::test_concurrent_imports**
   - **Time**: ~0.51s
   - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:108`
   - **Issue**: Creates 300 users across 3 batches
   - **Optimization**: Reduce batch size to 10 users each

### Category 2: OAuth Flow Tests (>0.4 seconds)

6. **CompleteUserJourneyTest::test_complete_oauth_authorization_flow**
   - **Time**: ~0.45-0.50s (estimated)
   - **Location**: `tests/Integration/EndToEnd/CompleteUserJourneyTest.php:108`
   - **Issue**: Performs full OAuth flow with PKCE multiple times
   - **Optimization**: Cache authorization codes, mock OAuth middleware

7. **CompleteUserJourneyTest::test_high_load_concurrent_requests**
   - **Time**: ~0.45s (estimated)
   - **Location**: `tests/Integration/EndToEnd/CompleteUserJourneyTest.php:393`
   - **Issue**: Creates 10 users + 25 concurrent requests
   - **Optimization**: Reduce to 3 users + 10 requests

8. **AdminPanelFlowsTest::test_admin_tenant_isolation_verification**
   - **Time**: ~0.47s
   - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php` (method line varies)
   - **Issue**: Creates multiple organizations with full data sets
   - **Optimization**: Reduce organization complexity

9. **AdminPanelFlowsTest::test_admin_role_permission_management**
   - **Time**: ~0.42s
   - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php` (method line varies)
   - **Issue**: Creates custom roles with extensive permission sets
   - **Optimization**: Minimize permission setup

10. **ApplicationAnalyticsTest::it_gets_token_generation_metrics_over_time**
    - **Time**: ~0.45-0.46s
    - **Location**: `tests/Integration/Applications/ApplicationAnalyticsTest.php`
    - **Issue**: Generates historical token data
    - **Optimization**: Pre-seed data in setUp(), reduce time range

### Category 3: Admin Panel & Organization Tests (>0.35 seconds)

11. **AdminPanelFlowsTest::test_admin_organization_switching**
    - **Time**: ~0.36s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: Creates multiple full organizations
    - **Optimization**: Reuse organizations from setUp()

12. **AdminPanelFlowsTest::test_admin_user_management_workflow**
    - **Time**: ~0.35s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: Full user CRUD workflow with relationships
    - **Optimization**: Streamline relationship creation

13. **OrganizationFlowsTest::test_organization_advanced_settings**
    - **Time**: ~0.30-0.35s (estimated)
    - **Location**: `tests/Integration/EndToEnd/OrganizationFlowsTest.php` (1527 lines)
    - **Issue**: Complex organization setup with all features
    - **Optimization**: Test features separately

14. **SsoFlowsTest::test_complete_oidc_flow_with_token_validation**
    - **Time**: ~0.30-0.35s (estimated)
    - **Location**: `tests/Integration/EndToEnd/SsoFlowsTest.php` (1390 lines)
    - **Issue**: Full SSO flow with JWT validation
    - **Optimization**: Mock JWT validation

15. **AdminPanelFlowsTest::test_super_admin_cross_organization_access**
    - **Time**: ~0.27s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: Creates multiple organizations for access testing
    - **Optimization**: Use setUp() organizations

### Category 4: Authentication & MFA Tests (>0.26 seconds)

16. **AdminPanelFlowsTest::test_admin_login_via_web**
    - **Time**: ~0.26s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: Full login flow with session setup
    - **Optimization**: Cache authenticated state

17. **AdminPanelFlowsTest::test_admin_mfa_enforcement**
    - **Time**: ~0.26s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: MFA setup + verification flow
    - **Optimization**: Pre-generate TOTP secrets

18. **AdminPanelFlowsTest::test_admin_session_management**
    - **Time**: ~0.26s
    - **Location**: `tests/Integration/EndToEnd/AdminPanelFlowsTest.php`
    - **Issue**: Multiple session operations
    - **Optimization**: Reduce session operations

19. **EndToEndTestCase::setupTestOrganizations**
    - **Time**: ~0.20-0.25s per test (overhead)
    - **Location**: `tests/Integration/EndToEnd/EndToEndTestCase.php:110`
    - **Issue**: Creates 2 full organizations in setUp() for every E2E test
    - **Optimization**: Use static organizations, share across tests

20. **BulkOperationsIntegrationTest::test_import_with_validation_errors**
    - **Time**: ~0.19s
    - **Location**: `tests/Integration/BulkOperationsIntegrationTest.php:148`
    - **Issue**: Creates 103 records to test validation
    - **Optimization**: Reduce to 20 records

## Performance Issues by Category

### 1. Database-Heavy Tests (5+ tests, ~4.5s total)

**Pattern**: Tests creating 100+ records to verify bulk operations

**Files Affected**:
- `BulkOperationsIntegrationTest.php` (7 tests)
- `CompleteUserJourneyTest.php` (test_high_load_concurrent_requests)

**Common Issues**:
```php
// SLOW: Creates 1000 users
User::factory()->count(1000)->create();

// BETTER: Creates 50 users (still validates bulk behavior)
User::factory()->count(50)->create();
```

**Optimization Potential**: **-3 seconds** (60% reduction)

### 2. Sleep Calls (7+ occurrences, ~7s total)

**Pattern**: Explicit sleep() calls to ensure timestamp differences

**Files Affected**:
- `TokenManagementTest.php:1` (sleep(1))
- `TokenRefreshTest.php:2` (sleep(1) x2)
- `SsoSessionLifecycleTest.php:2` (sleep(1) x2)
- `SsoTokenRefreshTest.php:3` (sleep(1) x3)

**Common Issues**:
```php
// SLOW: Hard sleep for timestamp difference
$firstToken = $this->createToken();
sleep(1);  // 1 second delay
$secondToken = $this->createToken();

// BETTER: Carbon::now()->addSecond() for explicit control
$firstToken = $this->createToken();
$this->travel(1)->seconds();  // Laravel time travel
$secondToken = $this->createToken();
$this->travelBack();
```

**Optimization Potential**: **-6 seconds** (85% reduction, keep 1s total)

### 3. OAuth Flow Overhead (20+ tests, ~10s total)

**Pattern**: Full OAuth authorization code flow repeated per test

**Files Affected**:
- `CompleteUserJourneyTest.php`
- `TokenRefreshTest.php`
- `AuthorizationCodeFlowTest.php`
- `OpenIdConnectTest.php`

**Common Issues**:
```php
// SLOW: Full OAuth flow every test
protected function performOAuthFlow(): array
{
    $this->get('/oauth/authorize?...');      // HTTP request
    preg_match('/auth_token/');              // Parse HTML
    $this->post('/oauth/authorize', ...);    // HTTP request
    parse_url($response->headers->get());    // Parse redirect
    $this->postJson('/oauth/token', ...);    // HTTP request
}

// BETTER: Cache authorization codes, mock middleware
protected function getAuthCode(User $user): string
{
    return DB::table('oauth_auth_codes')->insertGetId([...]);
}
```

**Optimization Potential**: **-4 seconds** (40% reduction)

### 4. Heavy Factory Usage (130+ occurrences)

**Pattern**: Creating full model hierarchies when simpler data would work

**Files Affected**: All organization and user tests

**Common Issues**:
```php
// SLOW: Creates user with all relationships
User::factory()->count(100)
    ->hasOrganization()
    ->hasRoles(3)
    ->hasPermissions(5)
    ->create();

// BETTER: Create minimal data
User::factory()->count(100)->create([
    'organization_id' => $this->organization->id,
]);
// Assign roles separately only if needed
```

**Optimization Potential**: **-5 seconds** (via reduced DB queries)

### 5. RefreshDatabase Overhead (30 test files)

**Pattern**: Full database refresh for every test class

**Files Affected**: All IntegrationTestCase subclasses

**Issue**:
```php
abstract class IntegrationTestCase extends TestCase
{
    use RefreshDatabase;  // Migrates DB for every test
}
```

**Better Approach**:
- Use database transactions where possible
- Share seeded data across tests in same class
- Consider in-memory SQLite for unit-style integration tests

**Optimization Potential**: **-10 seconds** (5% per-test reduction)

### 6. EndToEndTestCase Setup Overhead (20+ tests, ~5s total)

**Pattern**: Heavy setUp() creating multiple organizations and OAuth clients

**File**: `tests/Integration/EndToEnd/EndToEndTestCase.php`

**Issue**:
```php
protected function setUp(): void
{
    parent::setUp();
    $this->setupTestOrganizations();      // Creates 2 orgs
    $this->setupTestUsers();               // Creates 4 users
    $this->setupOAuthClients();            // Creates OAuth client
    $this->setupExternalServiceMocks();    // Sets up mocks
}
```

**Each E2E test pays this ~0.25s overhead!**

**Optimization Potential**: **-3 seconds** (use static data)

## Parallelization Analysis

### Tests Safe for Parallelization (70+ tests, ~140s)

**Characteristics**:
- No shared state dependencies
- Independent database transactions
- No time-sensitive operations
- No file system conflicts

**Examples**:
- All CRUD tests (Applications, Users, Organizations)
- Validation tests
- Cache tests
- Most API endpoint tests
- Authorization/permission tests

**Estimated Speedup**: 4-8x with 8 processes

### Tests Requiring Isolation (10+ tests, ~30s)

**Characteristics**:
- Manipulate global state (Cache, Config)
- Time-dependent (travel() calls)
- File system operations (exports, uploads)
- Shared database sequences

**Examples**:
- `CacheClearTest` (clears all caches)
- `test_token_expiration_*` (time travel)
- Bulk export tests (file conflicts)
- Security incident tests (global counters)

**Solution**: Group into separate test suite or add `@group isolated`

### Tests with Potential Race Conditions (5+ tests, ~10s)

**Characteristics**:
- Concurrent database writes to same records
- Sequential operations expecting specific order
- Webhook deliveries expecting no other activity

**Examples**:
- `test_concurrent_imports`
- Progressive lockout tests
- Intrusion detection tests

**Solution**: Use `@depends` or separate test groups

## Recommended ParaTest Configuration

### Option 1: Aggressive Parallelization (Fastest)

```xml
<!-- phpunit.xml -->
<phpunit>
    <extensions>
        <bootstrap class="ParaTest\Extension">
            <parameter name="runner" value="WrapperRunner"/>
            <parameter name="processes" value="8"/>
        </bootstrap>
    </extensions>
</phpunit>
```

**Expected Result**: 196s → 35-40s (80% reduction)

**Risks**: Race conditions, test pollution

### Option 2: Conservative Parallelization (Safest)

```bash
# Separate isolated tests
vendor/bin/paratest \
  --processes=6 \
  --exclude-group=isolated \
  tests/Integration/

# Run isolated tests sequentially
vendor/bin/phpunit \
  --group=isolated \
  tests/Integration/
```

**Expected Result**: 196s → 50-60s (65% reduction)

**Benefits**: No race conditions, predictable

### Option 3: Hybrid Approach (Recommended)

```bash
# Fast tests in parallel (8 processes)
vendor/bin/paratest \
  --processes=8 \
  --exclude-group=slow,isolated \
  tests/Integration/

# Slow tests in parallel (4 processes)
vendor/bin/paratest \
  --processes=4 \
  --group=slow \
  --exclude-group=isolated \
  tests/Integration/

# Isolated tests sequentially
vendor/bin/phpunit \
  --group=isolated \
  tests/Integration/
```

**Expected Result**: 196s → 45-50s (70% reduction)

**Benefits**: Optimal speed + safety

## Quick Wins (Immediate Impact)

### 1. Remove/Replace Sleep Calls (-6 seconds)

**Files**: 7 test files with sleep() calls

**Change**:
```php
// Before
sleep(1);

// After
$this->travel(1)->seconds();
// ... test code ...
$this->travelBack();
```

**Impact**: -6 seconds (85% of sleep time)

### 2. Reduce Bulk Test Sizes (-3 seconds)

**File**: `BulkOperationsIntegrationTest.php`

**Changes**:
- 1000 users → 100 users (test_large_import_of_users)
- 1000 users → 100 users (test_large_export_of_users)
- 500 users → 50 users (test_memory_usage_during_large_operations)
- 1000 users → 100 users (test_export_with_large_dataset_and_filters)
- 300 users → 30 users (test_concurrent_imports)

**Impact**: -3 seconds (60% reduction)

### 3. Cache OAuth Flow Setup (-4 seconds)

**Files**: All OAuth flow tests

**Implementation**:
```php
protected static ?string $cachedAuthCode = null;

protected function getCachedAuthCode(): string
{
    if (static::$cachedAuthCode === null) {
        static::$cachedAuthCode = $this->performOAuthFlow();
    }
    return static::$cachedAuthCode;
}
```

**Impact**: -4 seconds (40% reduction on OAuth tests)

### 4. Add Test Groups for Parallelization (-0s, enables future gains)

**Implementation**:
```php
// Add to slow tests
/**
 * @group slow
 */
class BulkOperationsIntegrationTest extends IntegrationTestCase

// Add to isolated tests
/**
 * @group isolated
 */
class CacheClearTest extends IntegrationTestCase
```

**Impact**: Enables 70% speedup with ParaTest

### 5. Static Organization Setup in E2E Tests (-3 seconds)

**File**: `EndToEndTestCase.php`

**Change**:
```php
protected static ?Organization $staticDefaultOrg = null;
protected static ?Organization $staticEnterpriseOrg = null;

protected function setupTestOrganizations(): void
{
    if (static::$staticDefaultOrg === null) {
        static::$staticDefaultOrg = Organization::factory()->create([...]);
        static::$staticEnterpriseOrg = Organization::factory()->create([...]);
    }

    $this->defaultOrganization = static::$staticDefaultOrg;
    $this->enterpriseOrganization = static::$staticEnterpriseOrg;
}
```

**Impact**: -3 seconds across 20+ E2E tests

## Summary of Optimization Potential

| Optimization | Impact | Effort | Priority |
|---|---|---|---|
| Remove sleep() calls | -6s | Low | High |
| Reduce bulk test sizes | -3s | Low | High |
| Static E2E setup | -3s | Low | High |
| Cache OAuth flows | -4s | Medium | High |
| Add test groups | -0s | Low | High |
| Enable ParaTest (conservative) | -130s | Low | High |
| Optimize factories | -5s | Medium | Medium |
| Database transactions | -10s | High | Medium |
| In-memory SQLite | -20s | High | Low |

**Total Potential Savings**:
- **Quick wins**: -16s (8% faster, 180s total)
- **With ParaTest**: -130s additional (40-50s total, 75% faster)
- **With all optimizations**: -181s (15s total, 92% faster)

## Recommended Action Plan

### Phase 1: Quick Wins (1 hour, -16 seconds)
1. Replace all sleep() calls with time travel
2. Reduce bulk operation test sizes
3. Add static organization setup to E2E tests
4. Add @group annotations

### Phase 2: Parallelization (1 hour, -130 seconds)
1. Configure ParaTest with conservative settings
2. Test for race conditions
3. Isolate problematic tests
4. Document parallel execution strategy

### Phase 3: Deep Optimization (4+ hours, -35 seconds)
1. Cache OAuth authorization codes
2. Optimize factory relationships
3. Add database transaction support
4. Consider in-memory SQLite for specific tests

**Recommended Priority**: Phase 1 + Phase 2 = -146 seconds (75% faster) for 2 hours work
