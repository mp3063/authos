# Test Quick Reference Guide

**Quick commands and examples for running tests in the Laravel 12 Authentication Service**

---

## Quick Start

```bash
# Run all tests (fast parallel execution)
./fast-tests.sh

# Run all tests (standard execution with timeout protection)
./run-tests.sh

# Run specific test file
./run-tests.sh tests/Integration/OAuth/AuthorizationCodeFlowTest.php

# Run specific test method
./run-tests.sh --filter=test_authorization_code_flow_with_pkce
```

---

## Test Execution Commands

### Parallel Execution (Fastest - 4-10x faster)

```bash
# All tests with auto-detected CPU cores
./fast-tests.sh

# All tests with custom process count
./fast-tests.sh --processes=8

# Specific directory
./fast-tests.sh tests/Unit
./fast-tests.sh tests/Integration

# Via composer
herd composer test:parallel              # All tests
herd composer test:parallel:unit         # Unit tests only
herd composer test:parallel:feature      # Feature tests only
```

### Standard Execution (With timeout protection)

```bash
# All tests
./run-tests.sh

# Specific directory
./run-tests.sh tests/Unit/
./run-tests.sh tests/Integration/OAuth/

# Specific file
./run-tests.sh tests/Integration/OAuth/AuthorizationCodeFlowTest.php

# Via composer
herd composer test                       # All tests
herd composer test:unit                  # Unit tests only
herd composer test:feature               # Feature tests only
```

### By Test Group

```bash
# Run tests by PHPUnit group
herd php artisan test --group=oauth
herd php artisan test --group=security
herd php artisan test --group=integration
herd php artisan test --group=critical

# Multiple groups
herd php artisan test --group=oauth --group=security

# Exclude groups
herd php artisan test --exclude-group=slow
```

### Coverage Reports

```bash
# Generate coverage report
herd composer test:coverage

# Coverage for specific directory
herd php vendor/bin/phpunit --coverage-html coverage tests/Unit

# For PhpStorm: Add -d memory_limit=1G to prevent exhaustion
herd php -d memory_limit=1G vendor/bin/phpunit --coverage-html coverage
```

---

## Test Categories

### Integration Tests (E2E)

**Location:** `tests/Integration/`

```bash
# All integration tests
./run-tests.sh tests/Integration/

# OAuth flows
./run-tests.sh tests/Integration/OAuth/

# Security tests
./run-tests.sh tests/Integration/Security/

# End-to-end complete workflows
./run-tests.sh tests/Integration/EndToEnd/

# Webhooks
./run-tests.sh tests/Integration/Webhooks/

# Background jobs
./run-tests.sh tests/Integration/Jobs/

# Organizations
./run-tests.sh tests/Integration/Organizations/

# Users
./run-tests.sh tests/Integration/Users/

# Applications
./run-tests.sh tests/Integration/Applications/

# Monitoring
./run-tests.sh tests/Integration/Monitoring/

# Enterprise features
./run-tests.sh tests/Integration/Enterprise/
```

### Unit Tests

**Location:** `tests/Unit/`

```bash
# All unit tests
./run-tests.sh tests/Unit/

# Service tests
./run-tests.sh tests/Unit/Services/

# Security services
./run-tests.sh tests/Unit/Services/Security/

# Job tests
./run-tests.sh tests/Unit/Jobs/
```

---

## Filtering Tests

### By Test Method Name

```bash
# Single test method
herd php artisan test --filter=test_oauth_flow

# Multiple methods (regex)
herd php artisan test --filter="/(test_oauth|test_token)/"

# Specific class and method
herd php artisan test --filter="OAuthFlowTest::test_authorization_code_flow"
```

### By Test Class

```bash
# Single class
herd php artisan test tests/Integration/OAuth/AuthorizationCodeFlowTest.php

# Multiple classes with wildcard
herd php artisan test tests/Integration/OAuth/*Test.php
```

---

## Debugging Failing Tests

### Verbose Output

```bash
# Standard verbose
herd php artisan test --verbose

# Very verbose (shows all test names)
herd php artisan test -vvv
```

### Stop on Failure

```bash
# Stop on first failure
herd php artisan test --stop-on-failure

# Stop on first error
herd php artisan test --stop-on-error
```

### Re-run Failed Tests

```bash
# PHPUnit caches failed tests
herd php vendor/bin/phpunit --cache-result

# Re-run only failed tests from last run
herd php vendor/bin/phpunit --cache-result --cache-result-file=.phpunit.result.cache
```

### Debug Specific Test

```bash
# Run single test with full output
herd php artisan test --filter=test_name -vvv

# Add dd() or dump() in test code
public function test_debug()
{
    $user = $this->createUser();
    dd($user); // Dump and die
    
    // Or use dump() to continue
    dump($user);
    dump($user->roles);
}
```

---

## Common Test Patterns

### Creating Test Data

```php
// User
$user = $this->createUser(['email' => 'test@example.com']);
$admin = $this->createUser([], 'Organization Admin');
$superAdmin = $this->createSuperAdmin();

// Organization
$org = $this->createOrganization(['name' => 'Test Org']);

// OAuth Application
$app = $this->createOAuthApplication(['name' => 'Test App']);

// Access Token
$token = $this->createAccessToken($user, ['*']);
```

### Authentication

```php
// Web authentication
$this->actingAs($user, 'web');

// API authentication (Passport)
$this->actingAs($user, 'api');
// or
$this->actingAsApiUser($user);

// With specific token
$token = $this->createAccessToken($user);
$response = $this->withToken($token)->getJson('/api/v1/endpoint');
```

### Making Requests

```php
// GET request
$response = $this->getJson('/api/v1/users');

// POST request
$response = $this->postJson('/api/v1/users', [
    'name' => 'Test User',
    'email' => 'test@example.com',
]);

// PUT request
$response = $this->putJson('/api/v1/users/1', ['name' => 'Updated']);

// DELETE request
$response = $this->deleteJson('/api/v1/users/1');

// With headers
$response = $this->withHeaders([
    'Authorization' => 'Bearer ' . $token,
    'Accept' => 'application/json',
])->getJson('/api/v1/users');
```

### Common Assertions

```php
// HTTP Status
$response->assertStatus(200);
$response->assertOk();
$response->assertCreated(); // 201
$response->assertNoContent(); // 204
$response->assertUnauthorized(); // 401
$response->assertForbidden(); // 403
$response->assertNotFound(); // 404
$response->assertUnprocessable(); // 422

// JSON Structure
$response->assertJsonStructure([
    'data' => ['id', 'name', 'email'],
]);

// JSON Values
$response->assertJson(['name' => 'Test']);
$response->assertJsonPath('data.name', 'Test');

// JSON Count
$response->assertJsonCount(10, 'data');

// Validation Errors
$response->assertJsonValidationErrors(['email', 'password']);

// Database
$this->assertDatabaseHas('users', ['email' => 'test@example.com']);
$this->assertDatabaseMissing('users', ['id' => 999]);
$this->assertDatabaseCount('users', 5);

// Model
$this->assertDatabaseHasModel($user);
$this->assertDatabaseMissingModel($deletedUser);

// Notifications
Notification::assertSentTo($user, WelcomeNotification::class);
Notification::assertNothingSent();

// Queue
Queue::assertPushed(ProcessJob::class);
Queue::assertNotPushed(ProcessJob::class);
```

---

## Helper Methods Reference

### TestCase (Base)

```php
// User creation
$user = $this->createUser($attributes, $role, $guard);
$admin = $this->createSuperAdmin($attributes);
$orgAdmin = $this->createOrganizationAdmin($attributes);

// Organization
$org = $this->createOrganization($attributes);

// Authentication
$user = $this->actingAsUser($user);
$admin = $this->actingAsAdmin($admin);
$user = $this->actingAsApiUser($user);

// Tokens
$token = $this->createAccessToken($user, $scopes, $clientId);
```

### IntegrationTestCase

```php
// OAuth
$app = $this->createOAuthApplication($attributes, $organization);
$token = $this->generateAccessToken($user, $scopes);

// PKCE
$pkce = $this->generatePkceChallenge('S256');
// Returns: ['verifier' => '...', 'challenge' => '...']

// Assertions
$this->assertAuthenticationLogged(['user_id' => $user->id, 'event' => 'login']);
$this->assertWebhookDeliveryCreated(['event_type' => 'user.created']);
$this->assertSecurityIncidentCreated(['type' => 'brute_force']);
$this->assertHasSecurityHeaders();
$this->assertOrganizationBoundaryEnforced($user, $url, $method);

// Utilities
$this->simulateFailedLoginAttempts($email, $attempts);
$this->waitFor($callback, $timeout, $interval);
```

### EndToEndTestCase

```php
// OAuth Flow
$tokens = $this->performOAuthFlow($user, $client, $scopes);

// Social Auth
$socialUser = $this->mockSuccessfulSocialAuth('google', $user);

// Multi-Organization
$orgs = $this->setupMultiOrganizationScenario();

// Time Travel
$this->travelToFuture(10); // 10 minutes
$this->travelToFutureHours(2); // 2 hours
$this->returnToPresent();

// Test Users
$user = $this->actingAsTestUser('regular');
$admin = $this->actingAsTestUser('super_admin');
$orgAdmin = $this->actingAsTestUser('organization_admin');

// Assertions
$this->assertOrganizationDataIsolation($user, $organization);
$this->assertAuditLogExists($user, $event, $additionalData);
$this->assertUnifiedApiResponse($response, $expectedStatus);

// Utilities
$responses = $this->simulateHighLoad($requests);
$headers = $this->getApiHeaders(['Custom-Header' => 'value']);
$log = $this->createAuthenticationLog($user, $event, $attributes);
```

---

## Environment & Configuration

### Test Database

Tests use in-memory SQLite database by default (configured in `phpunit.xml`):

```xml
<env name="DB_CONNECTION" value="sqlite"/>
<env name="DB_DATABASE" value=":memory:"/>
```

### Disable Specific Features for Testing

```xml
<env name="MAIL_MAILER" value="array"/>
<env name="QUEUE_CONNECTION" value="sync"/>
<env name="CACHE_DRIVER" value="array"/>
```

### Reset Database Between Tests

All test classes should use:
```php
use Illuminate\Foundation\Testing\RefreshDatabase;
```

---

## Performance Tips

### Parallel Testing (Fastest)

The `./fast-tests.sh` script runs tests in parallel using available CPU cores:
- Automatically detects CPU cores
- Distributes tests across processes
- 4-10x faster than sequential execution
- Safe for all test types

### Optimize Individual Tests

1. **Use factories efficiently:**
   ```php
   // Good: Create only what you need
   $user = User::factory()->create(['email' => 'test@example.com']);
   
   // Bad: Creating unnecessary data
   $org = Organization::factory()->create();
   $users = User::factory()->count(100)->create(); // Only if needed!
   ```

2. **Mock external services:**
   ```php
   // Mock LDAP, external APIs, etc.
   $mockLdap = Mockery::mock(LdapService::class);
   $mockLdap->shouldReceive('connect')->andReturnTrue();
   $this->app->instance(LdapService::class, $mockLdap);
   ```

3. **Use memory optimization:**
   ```php
   // RefreshDatabase uses transactions (much faster than migrations)
   use RefreshDatabase;
   ```

---

## Troubleshooting

### Test Hangs After Completion

**Issue:** PHPUnit may hang after all tests complete.

**Solution:** Use the wrapper script:
```bash
./run-tests.sh
```

Or manually `Ctrl+C` after seeing test results.

### Memory Exhaustion

**Issue:** `Allowed memory size exhausted`

**Solution:**
```bash
# Increase memory limit
herd php -d memory_limit=1G artisan test

# For coverage
herd php -d memory_limit=1G vendor/bin/phpunit --coverage-html coverage
```

### Permission Errors with Passport Keys

**Issue:** OAuth key permission errors

**Solution:**
```bash
herd php artisan passport:keys --force
chmod 600 storage/oauth-*.key
```

### Spatie Permission Cache Issues

**Issue:** Permission tests failing due to caching

**Solution:** Tests automatically clear permission cache in `setUp()` and `tearDown()`. If issues persist:
```bash
herd php artisan permission:cache-reset
```

### Database Issues

**Issue:** Database state persists between tests

**Solution:** Ensure `RefreshDatabase` trait is used:
```php
class MyTest extends TestCase
{
    use RefreshDatabase; // Essential!
}
```

### Time-Dependent Tests Failing

**Issue:** Token expiration tests fail

**Solution:** Use time helpers:
```php
// Travel forward in time
$this->travel(10)->minutes();

// Check token expired
$response = $this->getJson('/api/v1/auth/user');
$response->assertStatus(401);

// Return to present
$this->travelBack();
```

---

## Best Practices Checklist

- [ ] Use `#[Test]` attribute (not `@test` annotation)
- [ ] Use `RefreshDatabase` trait in all test classes
- [ ] Follow ARRANGE-ACT-ASSERT structure
- [ ] Use descriptive test method names
- [ ] Use factories for test data creation
- [ ] Mock external services (LDAP, APIs)
- [ ] Don't mock Laravel/framework features
- [ ] Test behavior, not implementation
- [ ] One assertion concept per test
- [ ] Group related tests with `@group` annotations

---

## Additional Resources

- **Full Patterns Guide:** `docs/testing-patterns.md`
- **Test Templates:** `tests/_templates/`
- **Existing Test Examples:**
  - E2E: `tests/Integration/EndToEnd/CompleteUserJourneyTest.php`
  - OAuth: `tests/Integration/OAuth/AuthorizationCodeFlowTest.php`
  - Security: `tests/Integration/Security/ProgressiveLockoutTest.php`
  - Webhooks: `tests/Integration/Webhooks/WebhookRetryFlowTest.php`
  - Jobs: `tests/Integration/Jobs/DeliverWebhookJobTest.php`
