# Test Optimization Guide

**Target Audience**: Developers optimizing Laravel integration test performance
**Project**: Laravel 12 Auth Service
**Last Updated**: 2025-11-06

---

## Table of Contents

1. [Optimization Principles](#optimization-principles)
2. [Before/After Examples](#beforeafter-examples)
3. [Optimization Techniques](#optimization-techniques)
4. [ParaTest Configuration](#paratest-configuration)
5. [Best Practices](#best-practices)
6. [Common Pitfalls](#common-pitfalls)
7. [Measurement & Validation](#measurement--validation)

---

## Optimization Principles

### The 80/20 Rule for Test Performance

**80% of test time comes from 20% of operations:**
- Database operations (factories, migrations)
- HTTP requests (OAuth flows, authentication)
- Sleep/wait operations
- File I/O operations

**Focus optimization efforts on**:
1. Tests taking >0.5 seconds
2. Tests with >10 database queries
3. Tests using sleep() or usleep()
4. Tests creating >50 records

### Optimization Priority Matrix

```
High Impact, Low Effort:
✓ Remove sleep() calls
✓ Reduce record counts in bulk tests
✓ Enable ParaTest

High Impact, Medium Effort:
✓ Cache OAuth flows
✓ Static setup data
✓ Optimize factory relationships

High Impact, High Effort:
✓ In-memory SQLite
✓ Database transaction isolation
✓ Mock external services

Low Impact:
✗ Micro-optimizations
✗ Premature abstraction
```

---

## Before/After Examples

### Example 1: Remove Sleep Calls

**Problem**: Using sleep() to ensure timestamp differences

```php
// ❌ BEFORE: Adds 1 second per test
public function test_token_rotation_on_refresh(): void
{
    $originalTokens = $this->performOAuthFlow();

    sleep(1);  // Wait to ensure different timestamp

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $originalTokens['refresh_token'],
    ]);
}

// ✅ AFTER: Instant, controlled time manipulation
public function test_token_rotation_on_refresh(): void
{
    $originalTokens = $this->performOAuthFlow();

    $this->travel(1)->seconds();  // Time travel instead of sleep

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $originalTokens['refresh_token'],
    ]);

    $this->travelBack();  // Return to present
}
```

**Performance Gain**: -1 second per test (7+ tests = -7 seconds total)

---

### Example 2: Reduce Bulk Operation Sizes

**Problem**: Testing with production-scale data

```php
// ❌ BEFORE: Creates 1000 users (1.5 seconds)
public function test_large_import_of_users(): void
{
    $records = array_map(function ($i) {
        return [
            'email' => "user{$i}@example.com",
            'name' => "User {$i}",
        ];
    }, range(1, 1000));  // 1000 records!

    $importJob = BulkImportJob::factory()->create([
        'total_records' => count($records),
        'records' => $records,
    ]);

    $processor = new ProcessBulkImportJob($importJob);
    $processor->handle();

    $this->assertEquals(1000, User::count());
}

// ✅ AFTER: Creates 100 users (0.3 seconds)
public function test_large_import_of_users(): void
{
    $records = array_map(function ($i) {
        return [
            'email' => "user{$i}@example.com",
            'name' => "User {$i}",
        ];
    }, range(1, 100));  // 100 records is enough to validate bulk logic

    $importJob = BulkImportJob::factory()->create([
        'total_records' => count($records),
        'records' => $records,
    ]);

    $processor = new ProcessBulkImportJob($importJob);
    $processor->handle();

    $this->assertEquals(100, User::count());
}
```

**Performance Gain**: -1.2 seconds per test (5 tests = -6 seconds total)

**Why it works**: Bulk operation logic is the same for 100 or 1000 records. The test validates the logic, not production capacity.

---

### Example 3: Cache OAuth Authorization Codes

**Problem**: Full OAuth flow repeated in every test

```php
// ❌ BEFORE: Full OAuth flow every test (0.4 seconds each)
public function test_token_refresh(): void
{
    // Perform complete OAuth flow
    $tokens = $this->performOAuthFlow();  // 0.4s

    // Test refresh logic
    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $tokens['refresh_token'],
    ]);
}

protected function performOAuthFlow(): array
{
    $this->actingAs($this->user, 'web');

    // Step 1: Request authorization (HTTP request)
    $authResponse = $this->get('/oauth/authorize?...');

    // Step 2: Parse HTML for auth token
    preg_match('/name="auth_token" value="([^"]+)"/', ...);

    // Step 3: Submit approval (HTTP request)
    $approvalResponse = $this->post('/oauth/authorize', ...);

    // Step 4: Exchange code for token (HTTP request)
    $tokenResponse = $this->postJson('/oauth/token', ...);

    return $tokenResponse->json();
}

// ✅ AFTER: Direct token creation (0.05 seconds)
public function test_token_refresh(): void
{
    // Create tokens directly
    $tokens = $this->createOAuthTokens($this->user);  // 0.05s

    // Test refresh logic
    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $tokens['refresh_token'],
    ]);
}

protected function createOAuthTokens(User $user): array
{
    // Create access token directly in database
    $accessToken = $user->createToken('Test Token', ['*'])->accessToken;

    // Create refresh token
    $refreshToken = RefreshToken::create([
        'id' => Str::random(100),
        'access_token_id' => $user->tokens()->latest()->first()->id,
        'revoked' => false,
        'expires_at' => now()->addDays(30),
    ]);

    return [
        'access_token' => $accessToken,
        'refresh_token' => encrypt($refreshToken->id),
        'token_type' => 'Bearer',
        'expires_in' => 3600,
    ];
}
```

**Performance Gain**: -0.35 seconds per test (20+ tests = -7 seconds total)

**When to use full OAuth flow**:
- Testing authorization code generation
- Testing PKCE validation
- Testing OAuth consent screen
- Testing OAuth error responses

**When to use direct token creation**:
- Testing token refresh
- Testing token revocation
- Testing API authorization
- Testing token introspection

---

### Example 4: Static Test Data Setup

**Problem**: Creating full data sets in setUp() for every test

```php
// ❌ BEFORE: Creates organizations for EVERY test (0.25s overhead per test)
abstract class EndToEndTestCase extends TestCase
{
    protected Organization $defaultOrganization;
    protected Organization $enterpriseOrganization;

    protected function setUp(): void
    {
        parent::setUp();

        // Creates 2 organizations with settings
        $this->defaultOrganization = Organization::factory()->create([
            'name' => 'Default Test Organization',
            'settings' => [...],  // Complex JSON
        ]);

        $this->enterpriseOrganization = Organization::factory()->create([
            'name' => 'Enterprise Test Organization',
            'settings' => [...],  // Complex JSON
        ]);
    }
}

// ✅ AFTER: Reuses static organizations (0.25s total for all tests)
abstract class EndToEndTestCase extends TestCase
{
    protected Organization $defaultOrganization;
    protected Organization $enterpriseOrganization;

    protected static ?Organization $staticDefaultOrg = null;
    protected static ?Organization $staticEnterpriseOrg = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Create once, reuse for all tests
        if (static::$staticDefaultOrg === null) {
            static::$staticDefaultOrg = Organization::factory()->create([
                'name' => 'Default Test Organization',
                'settings' => [...],
            ]);

            static::$staticEnterpriseOrg = Organization::factory()->create([
                'name' => 'Enterprise Test Organization',
                'settings' => [...],
            ]);
        }

        // Reference static instances
        $this->defaultOrganization = static::$staticDefaultOrg;
        $this->enterpriseOrganization = static::$staticEnterpriseOrg;
    }
}
```

**Performance Gain**: -0.20 seconds per test (20 tests = -4 seconds total)

**Important**: Only use for **read-only** test data. If tests modify the data, create fresh copies.

---

### Example 5: Optimize Factory Relationships

**Problem**: Creating unnecessary relationships

```php
// ❌ BEFORE: Creates users with all relationships (0.15s per user)
public function test_user_listing(): void
{
    User::factory()
        ->count(20)
        ->hasRoles(2)              // Unnecessary for listing test
        ->hasPermissions(5)        // Unnecessary for listing test
        ->hasSocialAccounts(1)     // Unnecessary for listing test
        ->create([
            'organization_id' => $this->organization->id,
        ]);

    $response = $this->getJson('/api/v1/users');
    $response->assertStatus(200);
}

// ✅ AFTER: Creates minimal data (0.03s per user)
public function test_user_listing(): void
{
    User::factory()
        ->count(20)
        ->create([
            'organization_id' => $this->organization->id,
        ]);

    $response = $this->getJson('/api/v1/users');
    $response->assertStatus(200);
}
```

**Performance Gain**: -0.12 seconds per user × 20 users = -2.4 seconds

**Rule of Thumb**: Only create relationships that are **tested** in that specific test.

---

### Example 6: Use Database Transactions

**Problem**: Full database migrations for every test

```php
// ❌ BEFORE: Full RefreshDatabase (0.5s overhead per test class)
class UserCrudTest extends IntegrationTestCase
{
    use RefreshDatabase;  // Drops and recreates entire DB

    public function test_create_user(): void { ... }
    public function test_update_user(): void { ... }
    public function test_delete_user(): void { ... }
}

// ✅ AFTER: Database transactions (0.05s overhead per test class)
class UserCrudTest extends IntegrationTestCase
{
    use DatabaseTransactions;  // Rollback after each test

    public function test_create_user(): void { ... }
    public function test_update_user(): void { ... }
    public function test_delete_user(): void { ... }
}
```

**Performance Gain**: -0.45 seconds per test class (30 classes = -13.5 seconds)

**When to use RefreshDatabase**:
- Testing migrations
- Testing database schema
- Testing seeders
- First test in CI pipeline

**When to use DatabaseTransactions**:
- Most integration tests
- Tests that don't modify schema
- Tests that need fresh data per test

---

## Optimization Techniques

### 1. Mock External Services

```php
// Instead of real HTTP calls
protected function mockStripeApi(): void
{
    Http::fake([
        'api.stripe.com/*' => Http::response([
            'id' => 'ch_test_123',
            'status' => 'succeeded',
        ], 200),
    ]);
}
```

**Use Case**: Testing payment integrations, webhooks, third-party APIs

---

### 2. Use In-Memory SQLite

```xml
<!-- phpunit.xml -->
<phpunit>
    <php>
        <env name="DB_CONNECTION" value="sqlite"/>
        <env name="DB_DATABASE" value=":memory:"/>
    </php>
</phpunit>
```

**Performance Gain**: 30-50% faster than PostgreSQL for tests

**Trade-offs**:
- ✅ Much faster
- ✅ No cleanup needed
- ❌ Different SQL dialect (may miss PostgreSQL-specific bugs)
- ❌ No foreign key constraints by default

**Recommendation**: Use for unit-style tests, use real database for integration tests

---

### 3. Batch Database Operations

```php
// ❌ SLOW: N queries
foreach ($users as $user) {
    $user->update(['status' => 'active']);
}

// ✅ FAST: 1 query
User::whereIn('id', $users->pluck('id'))
    ->update(['status' => 'active']);
```

---

### 4. Selective Test Execution

```bash
# Run only fast tests during development
vendor/bin/phpunit --exclude-group=slow

# Run all tests before commit
vendor/bin/phpunit

# Run only changed tests
vendor/bin/phpunit --filter=UserCrudTest
```

---

### 5. Use Test Doubles for Complex Objects

```php
// Instead of creating real Application
$app = Mockery::mock(Application::class);
$app->shouldReceive('getAttribute')
    ->with('client_id')
    ->andReturn('test_client_123');
```

**Use Case**: Testing business logic that depends on complex entities

---

## ParaTest Configuration

### Installation

```bash
composer require --dev brianium/paratest
```

### Basic Configuration

```xml
<!-- phpunit.xml -->
<phpunit>
    <!-- Existing config -->

    <extensions>
        <bootstrap class="ParaTest\Extension">
            <parameter name="runner" value="WrapperRunner"/>
            <parameter name="processes" value="auto"/>
        </bootstrap>
    </extensions>
</phpunit>
```

### Execution Strategies

#### Strategy 1: Full Parallelization (Fastest, Riskiest)

```bash
# Run all tests in parallel
vendor/bin/paratest --processes=8 tests/Integration/
```

**Expected Time**: 196s → 30s (85% faster)

**Risks**:
- Race conditions
- Database conflicts
- File system conflicts

---

#### Strategy 2: Conservative Parallelization (Recommended)

```bash
# Parallel safe tests
vendor/bin/paratest \
  --processes=8 \
  --exclude-group=isolated \
  tests/Integration/

# Sequential isolated tests
vendor/bin/phpunit \
  --group=isolated \
  tests/Integration/
```

**Expected Time**: 196s → 50s (75% faster)

**Tag isolated tests**:
```php
/**
 * @group isolated
 */
class CacheClearTest extends IntegrationTestCase
{
    // Tests that modify global state
}
```

---

#### Strategy 3: Hybrid Parallelization (Optimal)

```bash
#!/bin/bash
# fast-tests.sh

# Fast tests (8 processes)
vendor/bin/paratest \
  --processes=8 \
  --exclude-group=slow,isolated \
  tests/Integration/

# Slow tests (4 processes)
vendor/bin/paratest \
  --processes=4 \
  --group=slow \
  --exclude-group=isolated \
  tests/Integration/

# Isolated tests (sequential)
vendor/bin/phpunit \
  --group=isolated \
  tests/Integration/
```

**Expected Time**: 196s → 45s (77% faster)

**Tag slow tests**:
```php
/**
 * @group slow
 */
class BulkOperationsIntegrationTest extends IntegrationTestCase
{
    // Tests taking >0.5s
}
```

---

### ParaTest Environment Variables

```bash
# Control process count
PARATEST_PROCESSES=8 vendor/bin/paratest

# Enable verbose output
PARATEST_VERBOSE=1 vendor/bin/paratest

# Custom test path
PARATEST_PHPUNIT=vendor/bin/phpunit vendor/bin/paratest
```

---

### Handling Parallel Test Failures

#### Common Issues

1. **Database conflicts**:
   ```php
   // Use unique suffixes
   $org = Organization::factory()->create([
       'slug' => 'test-org-' . uniqid(),
   ]);
   ```

2. **File conflicts**:
   ```php
   // Use temporary directories
   $tempDir = sys_get_temp_dir() . '/test_' . uniqid();
   mkdir($tempDir);
   ```

3. **Cache conflicts**:
   ```php
   // Use test-specific cache keys
   Cache::put('test_' . $this->getName() . '_key', $value);
   ```

---

## Best Practices

### DO ✅

1. **Use appropriate test doubles**
   - Mock external APIs
   - Stub complex dependencies
   - Fake queues, mail, notifications

2. **Minimize database operations**
   - Create only necessary records
   - Batch operations when possible
   - Use transactions over RefreshDatabase

3. **Profile regularly**
   ```bash
   vendor/bin/phpunit --profile
   ```

4. **Tag tests appropriately**
   - `@group slow` for tests >0.5s
   - `@group isolated` for tests modifying global state
   - `@group integration` for full integration tests

5. **Use time travel over sleep**
   ```php
   $this->travel(5)->minutes();
   ```

### DON'T ❌

1. **Don't create unnecessary relationships**
   ```php
   // ❌ Bad
   User::factory()->hasRoles(5)->hasPosts(10)->create();

   // ✅ Good
   User::factory()->create();
   ```

2. **Don't use production-scale data**
   ```php
   // ❌ Bad: 1000 records
   User::factory()->count(1000)->create();

   // ✅ Good: 10-50 records
   User::factory()->count(20)->create();
   ```

3. **Don't test framework behavior**
   ```php
   // ❌ Bad: Testing Laravel's validation
   public function test_validation_rules_work()
   {
       $validator = Validator::make([], ['name' => 'required']);
       $this->assertTrue($validator->fails());
   }
   ```

4. **Don't share mutable state**
   ```php
   // ❌ Bad: Static shared array
   protected static $sharedUsers = [];

   // ✅ Good: Fresh data per test
   protected function createTestUser() { ... }
   ```

---

## Common Pitfalls

### Pitfall 1: Over-Parallelization

**Problem**: Running too many processes causes overhead

```bash
# ❌ Bad: 32 processes on 8-core CPU
vendor/bin/paratest --processes=32

# ✅ Good: 1.5x CPU cores
vendor/bin/paratest --processes=12
```

**Rule**: Use 1-2x your CPU core count

---

### Pitfall 2: Testing Implementation, Not Behavior

```php
// ❌ Bad: Testing internal implementation
public function test_user_repository_calls_database()
{
    $repo = app(UserRepository::class);
    $repo->shouldReceive('query')->once();
}

// ✅ Good: Testing observable behavior
public function test_user_can_be_retrieved()
{
    $user = User::factory()->create();

    $response = $this->getJson("/api/v1/users/{$user->id}");

    $response->assertStatus(200);
    $response->assertJson(['id' => $user->id]);
}
```

---

### Pitfall 3: Not Cleaning Up After Tests

```php
// ❌ Bad: Leaves time traveled
public function test_token_expiration()
{
    $this->travel(10)->days();
    // ... test code ...
    // Doesn't travel back!
}

// ✅ Good: Always clean up
public function test_token_expiration()
{
    $this->travel(10)->days();
    // ... test code ...
    $this->travelBack();
}
```

**Better**: Use tearDown()
```php
protected function tearDown(): void
{
    $this->travelBack();
    parent::tearDown();
}
```

---

### Pitfall 4: Ignoring Database Indexes

```php
// ❌ Slow: No index on organization_id
User::where('organization_id', $orgId)->get();

// ✅ Fast: Add index in migration
$table->index('organization_id');
```

Tests will expose missing indexes through slow queries!

---

## Measurement & Validation

### Before Optimization

```bash
# Run with profiling
time vendor/bin/phpunit --profile tests/Integration/

# Note baseline time and slow tests
```

### After Optimization

```bash
# Run again with profiling
time vendor/bin/phpunit --profile tests/Integration/

# Compare times
```

### Continuous Monitoring

```yaml
# .github/workflows/tests.yml
- name: Run tests with profiling
  run: |
    vendor/bin/phpunit --profile --log-junit junit.xml

- name: Upload timing data
  uses: actions/upload-artifact@v3
  with:
    name: test-timings
    path: junit.xml
```

---

## Example: Complete Optimization Workflow

### 1. Identify Slow Test

```bash
$ vendor/bin/phpunit --profile tests/Integration/

Tests\Integration\BulkOperationsIntegrationTest
✓ test_large_import_of_users    1.56s  ← SLOW!
```

### 2. Analyze Test Code

```php
public function test_large_import_of_users(): void
{
    $records = array_map(function ($i) {
        return ['email' => "user{$i}@example.com", ...];
    }, range(1, 1000));  ← Creating 1000 records!

    // ... rest of test
}
```

### 3. Apply Optimization

```php
public function test_large_import_of_users(): void
{
    $records = array_map(function ($i) {
        return ['email' => "user{$i}@example.com", ...];
    }, range(1, 100));  ← Reduced to 100 records

    // ... rest of test
}
```

### 4. Verify Improvement

```bash
$ vendor/bin/phpunit --profile tests/Integration/

Tests\Integration\BulkOperationsIntegrationTest
✓ test_large_import_of_users    0.31s  ← 80% faster!
```

### 5. Add Test Group

```php
/**
 * @group slow
 * Tests bulk import with 100 users (reduced from 1000 for test speed)
 */
public function test_large_import_of_users(): void
{
    // ... test code
}
```

### 6. Enable Parallelization

```bash
$ vendor/bin/paratest --processes=8 tests/Integration/

# All tests: 45s (was 196s)
# 77% improvement!
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│ Test Optimization Quick Reference                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ ⚡ QUICK WINS:                                          │
│   • Replace sleep() with time travel        -7s        │
│   • Reduce bulk test sizes                  -6s        │
│   • Static test data setup                  -4s        │
│   • Cache OAuth flows                       -7s        │
│   • Enable ParaTest                         -130s       │
│                                                         │
│ 📊 PROFILING:                                          │
│   vendor/bin/phpunit --profile                         │
│                                                         │
│ ⚙️ PARALLEL EXECUTION:                                 │
│   vendor/bin/paratest --processes=8                    │
│   vendor/bin/paratest --exclude-group=isolated         │
│                                                         │
│ 🏷️ TEST GROUPS:                                        │
│   @group slow       → Tests taking >0.5s               │
│   @group isolated   → Tests modifying global state     │
│                                                         │
│ 🎯 OPTIMIZATION TARGETS:                               │
│   • Tests >0.5s                                        │
│   • Tests with >10 DB queries                          │
│   • Tests using sleep()                                │
│   • Tests creating >50 records                         │
│                                                         │
│ ✅ BEST PRACTICES:                                     │
│   • Use DatabaseTransactions over RefreshDatabase      │
│   • Create minimal test data                           │
│   • Mock external services                             │
│   • Use time travel over sleep                         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Additional Resources

- [Laravel Testing Documentation](https://laravel.com/docs/testing)
- [PHPUnit Documentation](https://phpunit.de/documentation.html)
- [ParaTest Documentation](https://github.com/paratestphp/paratest)
- [Test Performance Analysis](./test-performance-analysis.md)

---

**Remember**: The goal is **fast feedback**, not just fast tests. Focus on optimizations that:
1. Provide immediate value (quick wins)
2. Don't sacrifice test quality
3. Enable parallel execution
4. Are maintainable long-term
