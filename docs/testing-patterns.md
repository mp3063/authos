# Testing Patterns & Best Practices

**Laravel 12 Authentication Service - Comprehensive Testing Guide**

This guide provides detailed patterns, best practices, and real examples for writing effective tests in this Laravel authentication service codebase.

---

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Types](#test-types)
3. [Common Testing Patterns](#common-testing-patterns)
4. [Helper Method Usage](#helper-method-usage)
5. [Testing Anti-Patterns](#testing-anti-patterns)
6. [Best Practices](#best-practices)
7. [Real-World Examples](#real-world-examples)

---

## Testing Philosophy

### Core Principles

1. **Test Behavior, Not Implementation**
   - Focus on WHAT the code does, not HOW it does it
   - Test from the user's perspective
   - Verify observable behavior and side effects

2. **Defense in Depth**
   - Critical features (security, authentication) tested at multiple levels
   - Unit tests for algorithms
   - Integration tests for workflows
   - E2E tests for complete user journeys

3. **Test Isolation**
   - Each test is independent
   - No shared state between tests
   - Use `RefreshDatabase` trait
   - Clear caches between tests

4. **Clear Test Intent**
   - Test names describe WHAT is being tested
   - Use ARRANGE-ACT-ASSERT structure
   - One assertion concept per test

---

## Test Types

### Integration Tests (E2E)

**Location:** `tests/Integration/`

**Purpose:** Test complete workflows with real HTTP requests, database interactions, and side effects.

**When to use:**
- Testing API endpoints
- Testing multi-step workflows
- Testing OAuth flows
- Verifying audit logs, notifications, webhooks
- Testing multi-tenant isolation

**Example:**
```php
#[Test]
public function user_can_complete_oauth_authorization_flow()
{
    // ARRANGE: Set up user and OAuth client
    $user = $this->createUser();
    $client = $this->createOAuthApplication();
    
    // ACT: Request authorization
    $this->actingAs($user, 'web');
    $response = $this->get('/oauth/authorize?' . http_build_query([
        'client_id' => $client->client_id,
        'redirect_uri' => $client->redirect_uris[0],
        'response_type' => 'code',
    ]));
    
    // ASSERT: Authorization page displayed
    $response->assertStatus(200);
    
    // ACT: User approves
    // ... continue flow
}
```

### Unit Tests

**Location:** `tests/Unit/`

**Purpose:** Test business logic in isolation from external dependencies.

**When to use:**
- Testing service class methods
- Testing algorithms and calculations
- Testing data transformations
- Testing validation logic
- Testing pure functions

**Example:**
```php
#[Test]
public function calculates_lockout_duration_correctly()
{
    // ARRANGE
    $service = new AccountLockoutService();
    
    // ACT
    $duration = $service->calculateLockoutDuration(5); // 5 attempts
    
    // ASSERT
    $this->assertEquals(15, $duration); // 15 minutes
}
```

### Background Job Tests

**Location:** `tests/Integration/Jobs/`

**Purpose:** Test job dispatch, configuration, execution, and error handling.

**When to use:**
- Testing job dispatch
- Testing job configuration (queue, timeout, retries)
- Testing successful execution
- Testing failure handling
- Testing external service interaction

**Example:**
```php
#[Test]
public function job_handles_external_service_failure()
{
    // ARRANGE: Mock failing service
    $mockService = Mockery::mock(WebhookService::class);
    $mockService->shouldReceive('deliver')
        ->once()
        ->andThrow(new \Exception('Service unavailable'));
    
    $this->app->instance(WebhookService::class, $mockService);
    
    // ACT & ASSERT
    $job = new DeliverWebhookJob($delivery);
    $this->expectException(\Exception::class);
    $job->handle($mockService);
}
```

---

## Common Testing Patterns

### Pattern 1: Complete E2E Flow Testing

**Use Case:** Testing entire user journeys from start to finish.

**Structure:**
```php
#[Test]
public function user_can_complete_registration_to_first_action_flow()
{
    // Step 1: Registration
    $response = $this->postJson('/api/v1/auth/register', [...]);
    $response->assertStatus(201);
    $userId = $response->json('user.id');
    
    // Step 2: Email verification (if required)
    // ...
    
    // Step 3: First login
    $loginResponse = $this->postJson('/api/v1/auth/login', [...]);
    $loginResponse->assertStatus(200);
    $token = $loginResponse->json('access_token');
    
    // Step 4: Perform authenticated action
    $this->withToken($token)
        ->postJson('/api/v1/resource', [...])
        ->assertStatus(201);
    
    // Verify side effects
    $this->assertDatabaseHas('authentication_logs', [
        'user_id' => $userId,
        'event' => 'login_success',
    ]);
}
```

**Real Example:** `tests/Integration/EndToEnd/CompleteUserJourneyTest.php`

---

### Pattern 2: Multi-Tenant Isolation Testing

**Use Case:** Ensuring users can only access their organization's data.

**Structure:**
```php
#[Test]
public function user_cannot_access_resource_from_different_organization()
{
    // ARRANGE: Two organizations
    $org1 = $this->createOrganization();
    $org2 = $this->createOrganization();
    
    $user1 = $this->createUser(['organization_id' => $org1->id]);
    $resource2 = Resource::factory()->create(['organization_id' => $org2->id]);
    
    // ACT: User from org1 attempts to access org2's resource
    $this->actingAs($user1, 'api');
    $response = $this->getJson("/api/v1/resources/{$resource2->id}");
    
    // ASSERT: 404 (not 403) to prevent information leakage
    $response->assertStatus(404);
}
```

**Real Examples:**
- `tests/Integration/Security/OrganizationBoundaryTest.php`
- `tests/Integration/EndToEnd/CompleteUserJourneyTest.php::test_multi_organization_data_isolation()`

---

### Pattern 3: OAuth Authorization Flow Testing

**Use Case:** Testing complete OAuth 2.0 authorization code flow with PKCE.

**Structure:**
```php
#[Test]
public function oauth_authorization_code_flow_with_pkce()
{
    // ARRANGE: Generate PKCE challenge
    $pkce = $this->generatePkceChallenge('S256');
    
    // Step 1: Request authorization
    $this->actingAs($user, 'web');
    $authResponse = $this->get('/oauth/authorize?' . http_build_query([
        'client_id' => $client->id,
        'redirect_uri' => $client->redirect,
        'response_type' => 'code',
        'code_challenge' => $pkce['challenge'],
        'code_challenge_method' => 'S256',
    ]));
    
    // Step 2: Extract auth_token and approve
    preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
    $authToken = $matches[1];
    
    $approvalResponse = $this->post('/oauth/authorize', [
        'auth_token' => $authToken,
        'approve' => '1',
    ]);
    
    // Step 3: Extract authorization code
    $redirectUrl = $approvalResponse->headers->get('Location');
    parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $query);
    $code = $query['code'];
    
    // Step 4: Exchange code for tokens
    $tokenResponse = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->id,
        'client_secret' => $client->secret,
        'code' => $code,
        'redirect_uri' => $client->redirect,
        'code_verifier' => $pkce['verifier'],
    ]);
    
    $tokenResponse->assertStatus(200);
    $tokenResponse->assertJsonStructure(['access_token', 'refresh_token']);
}
```

**Real Example:** `tests/Integration/OAuth/AuthorizationCodeFlowTest.php`

---

### Pattern 4: Webhook Delivery and Retry Testing

**Use Case:** Testing webhook event dispatch, delivery, and retry logic.

**Structure:**
```php
#[Test]
public function webhook_retries_on_failure_with_exponential_backoff()
{
    // ARRANGE: Create webhook and delivery
    $webhook = Webhook::factory()->create(['url' => 'https://example.com/webhook']);
    $delivery = WebhookDelivery::factory()->create([
        'webhook_id' => $webhook->id,
        'status' => 'pending',
    ]);
    
    // ARRANGE: Mock HTTP client to fail initially
    Http::fake([
        'example.com/*' => Http::sequence()
            ->push(['error' => 'timeout'], 500) // Attempt 1
            ->push(['error' => 'timeout'], 500) // Attempt 2
            ->push(['success' => true], 200),   // Attempt 3
    ]);
    
    // ACT: Dispatch job multiple times
    for ($i = 0; $i < 3; $i++) {
        DeliverWebhookJob::dispatchSync($delivery);
        $delivery->refresh();
    }
    
    // ASSERT: Final delivery successful
    $this->assertEquals('delivered', $delivery->status);
    $this->assertEquals(3, $delivery->attempts);
}
```

**Real Examples:**
- `tests/Integration/Webhooks/WebhookRetryFlowTest.php`
- `tests/Integration/Webhooks/WebhookDeliveryFlowTest.php`

---

### Pattern 5: Cache Invalidation Testing

**Use Case:** Verifying that cache is properly invalidated when data changes.

**Structure:**
```php
#[Test]
public function updating_resource_invalidates_cache()
{
    // ARRANGE: Create and cache resource
    $resource = Resource::factory()->create();
    $cacheKey = "resource:{$resource->id}";
    Cache::put($cacheKey, $resource, 3600);
    
    // Verify cache exists
    $this->assertNotNull(Cache::get($cacheKey));
    
    // ACT: Update resource
    $this->actingAs($user, 'api');
    $this->putJson("/api/v1/resources/{$resource->id}", [
        'name' => 'Updated Name',
    ]);
    
    // ASSERT: Cache invalidated
    $this->assertNull(Cache::get($cacheKey));
}
```

**Real Example:** `tests/Integration/Cache/ApiCachingTest.php`

---

### Pattern 6: Background Job Testing

**Use Case:** Testing job dispatch, execution, and failure handling.

**Structure:**
```php
#[Test]
public function job_can_be_dispatched_and_executed()
{
    // ARRANGE
    Queue::fake();
    $model = Model::factory()->create();
    
    // ACT: Dispatch job
    ProcessModelJob::dispatch($model);
    
    // ASSERT: Job dispatched
    Queue::assertPushed(ProcessModelJob::class, function ($job) use ($model) {
        return $job->model->id === $model->id;
    });
    
    // ACT: Execute job
    Queue::fake(); // Reset
    $mockService = Mockery::mock(Service::class);
    $mockService->shouldReceive('process')->once()->andReturnTrue();
    $this->app->instance(Service::class, $mockService);
    
    $job = new ProcessModelJob($model);
    $job->handle($mockService);
    
    // ASSERT: Model updated
    $model->refresh();
    $this->assertEquals('processed', $model->status);
}
```

**Real Example:** `tests/Integration/Jobs/DeliverWebhookJobTest.php`

---

### Pattern 7: Security Testing (Progressive Lockout)

**Use Case:** Testing progressive account lockout on repeated failed login attempts.

**Structure:**
```php
#[Test]
public function account_locks_progressively_based_on_failed_attempts()
{
    $testCases = [
        ['attempts' => 3, 'lockout_minutes' => 5],
        ['attempts' => 5, 'lockout_minutes' => 15],
        ['attempts' => 7, 'lockout_minutes' => 30],
        ['attempts' => 10, 'lockout_minutes' => 60],
        ['attempts' => 15, 'lockout_minutes' => 1440],
    ];
    
    foreach ($testCases as $case) {
        // ARRANGE: Fresh user
        $user = $this->createUser(['email' => "test{$case['attempts']}@example.com"]);
        
        // ACT: Create failed attempts
        for ($i = 0; $i < $case['attempts']; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'attempted_at' => now(),
            ]);
        }
        
        $lockout = $lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');
        
        // ASSERT: Correct lockout duration
        $this->assertNotNull($lockout);
        $this->assertEqualsWithDelta(
            $case['lockout_minutes'],
            now()->diffInMinutes($lockout->unlock_at),
            1 // Allow 1 minute variance
        );
    }
}
```

**Real Example:** `tests/Integration/Security/ProgressiveLockoutTest.php`

---

### Pattern 8: Side Effect Verification

**Use Case:** Ensuring actions trigger expected side effects (logs, notifications, webhooks).

**Structure:**
```php
#[Test]
public function action_triggers_all_expected_side_effects()
{
    // ARRANGE
    $user = $this->createUser();
    $resource = Resource::factory()->create(['user_id' => $user->id]);
    Notification::fake();
    
    // ACT: Perform action
    $this->actingAs($user, 'api');
    $this->postJson("/api/v1/resources/{$resource->id}/activate");
    
    // ASSERT: Database updated
    $resource->refresh();
    $this->assertTrue($resource->is_active);
    
    // ASSERT: Audit log created
    $this->assertDatabaseHas('authentication_logs', [
        'user_id' => $user->id,
        'event' => 'resource_activated',
    ]);
    
    // ASSERT: Notification sent
    Notification::assertSentTo($user, ResourceActivatedNotification::class);
    
    // ASSERT: Webhook dispatched
    $this->assertDatabaseHas('webhook_deliveries', [
        'event_type' => 'resource.activated',
    ]);
}
```

---

## Helper Method Usage

### Base TestCase Helpers

**Location:** `tests/TestCase.php`

#### createUser()
```php
// Basic user
$user = $this->createUser();

// User with specific attributes
$user = $this->createUser([
    'email' => 'custom@example.com',
    'organization_id' => $org->id,
]);

// User with specific role
$admin = $this->createUser([], 'Organization Admin');
$apiUser = $this->createUser([], 'User', 'api');
```

#### createOrganization()
```php
$org = $this->createOrganization([
    'name' => 'Test Org',
    'settings' => ['mfa_required' => true],
]);
```

#### actingAsApiUser()
```php
// Act as user with Passport token
$user = $this->actingAsApiUser($user);

// Create new user and act as them
$user = $this->actingAsApiUser();
```

#### createAccessToken()
```php
// Create token for user
$token = $this->createAccessToken($user);

// With specific scopes
$token = $this->createAccessToken($user, ['read', 'write']);

// With specific client
$token = $this->createAccessToken($user, ['*'], $client->id);
```

### IntegrationTestCase Helpers

**Location:** `tests/Integration/IntegrationTestCase.php`

#### createOAuthApplication()
```php
$app = $this->createOAuthApplication([
    'name' => 'Test App',
    'organization_id' => $org->id,
]);
```

#### generatePkceChallenge()
```php
$pkce = $this->generatePkceChallenge('S256');
// Returns: ['verifier' => '...', 'challenge' => '...']
```

#### assertAuthenticationLogged()
```php
$this->assertAuthenticationLogged([
    'user_id' => $user->id,
    'event' => 'login_success',
]);
```

#### assertWebhookDeliveryCreated()
```php
$this->assertWebhookDeliveryCreated([
    'event_type' => 'user.created',
    'status' => 'pending',
]);
```

#### assertSecurityIncidentCreated()
```php
$this->assertSecurityIncidentCreated([
    'type' => 'brute_force_attempt',
    'severity' => 'high',
]);
```

### EndToEndTestCase Helpers

**Location:** `tests/Integration/EndToEnd/EndToEndTestCase.php`

#### performOAuthFlow()
```php
// Complete OAuth flow, returns tokens
$tokens = $this->performOAuthFlow($user, $client);
$accessToken = $tokens['access_token'];
$refreshToken = $tokens['refresh_token'];
```

#### mockSuccessfulSocialAuth()
```php
// Mock social auth for testing
$socialUser = $this->mockSuccessfulSocialAuth('google');
```

#### setupMultiOrganizationScenario()
```php
// Create 3 orgs with users and apps
$orgs = $this->setupMultiOrganizationScenario();
// Returns: [['organization' => ..., 'admin' => ..., 'users' => [...], 'application' => ...], ...]
```

#### travelToFuture() / returnToPresent()
```php
// Travel 10 minutes forward
$this->travelToFuture(10);

// Test token expiration
$response = $this->get('/api/v1/auth/user');
$response->assertStatus(401);

// Return to present
$this->returnToPresent();
```

---

## Testing Anti-Patterns

### Anti-Pattern 1: Testing Implementation Details

**BAD:**
```php
#[Test]
public function service_calls_repository_with_correct_parameters()
{
    $mockRepo = Mockery::mock(Repository::class);
    $mockRepo->shouldReceive('save')->once()->with(Mockery::type('array'));
    
    $service = new Service($mockRepo);
    $service->process(['data' => 'value']);
}
```

**GOOD:**
```php
#[Test]
public function service_saves_data_correctly()
{
    $service = new Service();
    $result = $service->process(['data' => 'value']);
    
    $this->assertDatabaseHas('table', ['data' => 'value']);
    $this->assertTrue($result);
}
```

**Why:** Testing implementation ties tests to internal structure. Tests should verify behavior, not how it's implemented.

---

### Anti-Pattern 2: Over-Mocking

**BAD:**
```php
#[Test]
public function complex_flow_with_all_mocks()
{
    $mockRepo = Mockery::mock(Repository::class);
    $mockCache = Mockery::mock(Cache::class);
    $mockLogger = Mockery::mock(Logger::class);
    $mockValidator = Mockery::mock(Validator::class);
    
    // 50 lines of mock setup...
    // Test becomes maintenance nightmare
}
```

**GOOD:**
```php
#[Test]
public function complex_flow_uses_real_components()
{
    // Use real database, cache (can be memory)
    // Only mock external services (APIs, LDAP, etc.)
    
    $mockExternalApi = Mockery::mock(ExternalApi::class);
    $mockExternalApi->shouldReceive('call')->once()->andReturn(['success' => true]);
    
    $service = new Service($mockExternalApi);
    $result = $service->process($data);
    
    $this->assertTrue($result);
}
```

**Why:** Over-mocking leads to testing mocks instead of real behavior. Use real components where possible.

---

### Anti-Pattern 3: Testing Framework Features

**BAD:**
```php
#[Test]
public function eloquent_save_persists_to_database()
{
    $model = new Model(['name' => 'Test']);
    $model->save();
    
    $this->assertDatabaseHas('models', ['name' => 'Test']);
}
```

**GOOD:**
```php
#[Test]
public function create_user_endpoint_validates_email()
{
    $response = $this->postJson('/api/v1/users', [
        'email' => 'invalid-email',
        'name' => 'Test',
    ]);
    
    $response->assertStatus(422);
    $response->assertJsonValidationErrors(['email']);
}
```

**Why:** Don't test Laravel/framework features. Test YOUR business logic.

---

### Anti-Pattern 4: Brittle Assertions

**BAD:**
```php
#[Test]
public function returns_users()
{
    User::factory()->count(3)->create();
    
    $response = $this->getJson('/api/v1/users');
    
    // Brittle: Depends on exact array structure
    $this->assertEquals([
        ['id' => 1, 'name' => 'User 1'],
        ['id' => 2, 'name' => 'User 2'],
        ['id' => 3, 'name' => 'User 3'],
    ], $response->json('data'));
}
```

**GOOD:**
```php
#[Test]
public function returns_users()
{
    User::factory()->count(3)->create();
    
    $response = $this->getJson('/api/v1/users');
    
    $response->assertStatus(200);
    $response->assertJsonCount(3, 'data');
    $response->assertJsonStructure([
        'data' => [
            '*' => ['id', 'name', 'email'],
        ],
    ]);
}
```

**Why:** Assert structure and key properties, not exact values. Tests should be resilient to minor changes.

---

### Anti-Pattern 5: Shared Test State

**BAD:**
```php
class UserTest extends TestCase
{
    private static $user; // Shared across tests!
    
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::$user = User::factory()->create();
    }
    
    #[Test]
    public function test_a() { /* uses self::$user */ }
    
    #[Test]
    public function test_b() { /* modifies self::$user */ }
}
```

**GOOD:**
```php
class UserTest extends TestCase
{
    #[Test]
    public function test_a()
    {
        $user = User::factory()->create(); // Fresh user
        // Test with $user
    }
    
    #[Test]
    public function test_b()
    {
        $user = User::factory()->create(); // Fresh user
        // Test with $user
    }
}
```

**Why:** Shared state causes test interdependence. Each test should be completely isolated.

---

## Best Practices

### 1. Use PHP 8 Attributes

**ALWAYS use `#[Test]` attribute:**
```php
#[Test]
public function user_can_login() { }
```

**NEVER use `@test` annotation:**
```php
/** @test */ // DON'T USE
public function user_can_login() { }
```

### 2. ARRANGE-ACT-ASSERT Structure

```php
#[Test]
public function user_can_update_profile()
{
    // ARRANGE: Set up test data and preconditions
    $user = $this->createUser();
    $newData = ['name' => 'Updated Name'];
    
    // ACT: Execute the action being tested
    $this->actingAs($user, 'api');
    $response = $this->putJson('/api/v1/profile', $newData);
    
    // ASSERT: Verify expected outcomes
    $response->assertStatus(200);
    $user->refresh();
    $this->assertEquals('Updated Name', $user->name);
}
```

### 3. Descriptive Test Names

**GOOD:**
```php
public function user_cannot_delete_resource_from_different_organization()
public function oauth_token_expires_after_configured_duration()
public function progressive_lockout_increases_duration_with_attempts()
```

**BAD:**
```php
public function test1()
public function it_works()
public function delete_test()
```

### 4. RefreshDatabase for Isolation

**ALWAYS use RefreshDatabase:**
```php
class MyTest extends TestCase
{
    use RefreshDatabase; // Essential for test isolation
}
```

### 5. Factory Usage

**Use factories instead of manual creation:**
```php
// GOOD
$user = User::factory()->create(['email' => 'test@example.com']);
$users = User::factory()->count(10)->create();

// BAD
$user = new User();
$user->name = 'Test';
$user->email = 'test@example.com';
$user->password = bcrypt('password');
$user->save();
```

### 6. Inline Documentation

For complex tests, add inline comments explaining WHY:
```php
#[Test]
public function refresh_token_rotation_prevents_replay_attacks()
{
    // Use refresh token once
    $tokens1 = $this->useRefreshToken($refreshToken);
    
    // RFC 6749 Section 10.4: Old refresh tokens MUST be invalidated
    // This prevents token replay attacks where attacker uses stolen refresh token
    $tokens2 = $this->useRefreshToken($refreshToken); // Should fail
    
    $tokens2->assertStatus(400);
}
```

### 7. Group Related Tests

Use PHPUnit groups for easier test execution:
```php
/**
 * @group integration
 * @group oauth
 * @group critical
 */
class OAuthFlowTest extends IntegrationTestCase
{
    // ...
}
```

Run specific groups:
```bash
php artisan test --group=oauth
php artisan test --group=critical
```

---

## Real-World Examples

### Example 1: Complete OAuth Flow

**File:** `tests/Integration/OAuth/AuthorizationCodeFlowTest.php`

```php
#[Test]
public function authorization_code_flow_with_pkce_s256()
{
    // ARRANGE: User and OAuth client
    $user = $this->createUser();
    $client = $this->createOAuthApplication();
    
    // ARRANGE: Generate PKCE challenge
    $codeVerifier = \Illuminate\Support\Str::random(64);
    $codeChallenge = rtrim(
        strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'),
        '='
    );
    
    // ACT: Step 1 - Request authorization
    $this->actingAs($user, 'web');
    $authParams = [
        'client_id' => $client->client_id,
        'redirect_uri' => $client->redirect_uris[0],
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'state' => 'random_state',
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => 'S256',
    ];
    
    $authResponse = $this->get('/oauth/authorize?' . http_build_query($authParams));
    $authResponse->assertStatus(200);
    
    // ACT: Step 2 - Extract and submit auth_token
    preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
    $authToken = $matches[1];
    
    $approvalResponse = $this->post('/oauth/authorize', [
        'state' => $authParams['state'],
        'client_id' => $authParams['client_id'],
        'auth_token' => $authToken,
    ]);
    
    // ASSERT: Redirect with authorization code
    $approvalResponse->assertRedirect();
    $redirectUrl = $approvalResponse->headers->get('Location');
    $this->assertStringContainsString('code=', $redirectUrl);
    
    // ACT: Step 3 - Extract code and exchange for tokens
    parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);
    $authCode = $queryParams['code'];
    
    $tokenResponse = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client_id,
        'client_secret' => $client->client_secret,
        'code' => $authCode,
        'redirect_uri' => $client->redirect_uris[0],
        'code_verifier' => $codeVerifier, // PKCE verification
    ]);
    
    // ASSERT: Tokens issued
    $tokenResponse->assertStatus(200);
    $tokenData = $tokenResponse->json();
    $this->assertArrayHasKey('access_token', $tokenData);
    $this->assertArrayHasKey('refresh_token', $tokenData);
    $this->assertArrayHasKey('expires_in', $tokenData);
    $this->assertEquals('Bearer', $tokenData['token_type']);
    
    // ACT: Step 4 - Use access token
    $userInfoResponse = $this->getJson('/api/v1/oauth/userinfo', [
        'Authorization' => 'Bearer ' . $tokenData['access_token'],
    ]);
    
    // ASSERT: User info retrieved
    $userInfoResponse->assertStatus(200);
    $userInfoResponse->assertJson([
        'sub' => (string) $user->id,
        'email' => $user->email,
    ]);
}
```

### Example 2: Multi-Tenant Isolation

**File:** `tests/Integration/Security/OrganizationBoundaryTest.php`

```php
#[Test]
public function users_from_different_organizations_cannot_access_each_others_data()
{
    // ARRANGE: Two organizations
    $org1 = $this->createOrganization(['name' => 'Organization 1']);
    $org2 = $this->createOrganization(['name' => 'Organization 2']);
    
    // ARRANGE: Users in each organization
    $user1 = $this->createUser(['organization_id' => $org1->id], 'Organization Admin');
    $user2 = $this->createUser(['organization_id' => $org2->id], 'Organization Admin');
    
    // ARRANGE: Resources in each organization
    $app1 = Application::factory()->create(['organization_id' => $org1->id]);
    $app2 = Application::factory()->create(['organization_id' => $org2->id]);
    
    // ACT: User1 tries to access User2's application
    $this->actingAs($user1, 'api');
    $response = $this->getJson("/api/v1/applications/{$app2->id}");
    
    // ASSERT: Not found (404, not 403 to prevent info leakage)
    $response->assertStatus(404);
    
    // ASSERT: User1 can access their own application
    $ownResponse = $this->getJson("/api/v1/applications/{$app1->id}");
    $ownResponse->assertStatus(200);
    $ownResponse->assertJson(['id' => $app1->id]);
    
    // ASSERT: Verify no data leakage in error response
    $responseData = $response->json();
    $this->assertArrayNotHasKey('organization_id', $responseData);
}
```

### Example 3: Webhook Retry Logic

**File:** `tests/Integration/Webhooks/WebhookRetryFlowTest.php`

```php
#[Test]
public function webhook_retries_with_exponential_backoff_on_failure()
{
    // ARRANGE: Webhook and delivery
    $webhook = Webhook::factory()->create([
        'url' => 'https://example.com/webhook',
        'max_retries' => 3,
        'retry_backoff' => 'exponential',
    ]);
    
    $delivery = WebhookDelivery::factory()->create([
        'webhook_id' => $webhook->id,
        'event_type' => 'user.created',
        'status' => 'pending',
        'attempts' => 0,
    ]);
    
    // ARRANGE: Mock HTTP failures then success
    Http::fake([
        'example.com/*' => Http::sequence()
            ->push(['error' => 'Service unavailable'], 503)  // Attempt 1
            ->push(['error' => 'Timeout'], 504)             // Attempt 2
            ->push(['success' => true], 200),               // Attempt 3
    ]);
    
    // ACT: Attempt 1 (immediate)
    DeliverWebhookJob::dispatchSync($delivery);
    $delivery->refresh();
    
    // ASSERT: Failed, scheduled for retry
    $this->assertEquals('failed', $delivery->status);
    $this->assertEquals(1, $delivery->attempts);
    $this->assertNotNull($delivery->next_retry_at);
    
    // ASSERT: Retry scheduled with backoff (1 minute)
    $expectedRetry = now()->addMinutes(1);
    $this->assertEqualsWithDelta(
        $expectedRetry->timestamp,
        $delivery->next_retry_at->timestamp,
        5 // Allow 5 second variance
    );
    
    // ACT: Attempt 2 (after 1 minute)
    $this->travel(1)->minutes();
    DeliverWebhookJob::dispatchSync($delivery);
    $delivery->refresh();
    
    // ASSERT: Failed again, longer backoff (2 minutes)
    $this->assertEquals(2, $delivery->attempts);
    $expectedRetry = now()->addMinutes(2);
    $this->assertEqualsWithDelta(
        $expectedRetry->timestamp,
        $delivery->next_retry_at->timestamp,
        5
    );
    
    // ACT: Attempt 3 (after 2 minutes)
    $this->travel(2)->minutes();
    DeliverWebhookJob::dispatchSync($delivery);
    $delivery->refresh();
    
    // ASSERT: Success
    $this->assertEquals('delivered', $delivery->status);
    $this->assertEquals(3, $delivery->attempts);
    $this->assertNotNull($delivery->delivered_at);
    $this->assertEquals(200, $delivery->response_status);
}
```

---

## Summary

This guide provides comprehensive patterns for writing effective tests in the Laravel authentication service. Key takeaways:

1. **Choose the right test type** - Integration for workflows, Unit for logic, Jobs for background tasks
2. **Follow patterns** - E2E flows, multi-tenant isolation, OAuth flows, webhooks, security
3. **Use helpers** - Leverage TestCase, IntegrationTestCase, and EndToEndTestCase helpers
4. **Avoid anti-patterns** - Don't test implementation, don't over-mock, don't share state
5. **Follow best practices** - PHP 8 attributes, ARRANGE-ACT-ASSERT, descriptive names, factories

For specific examples, refer to the existing test files in:
- `tests/Integration/EndToEnd/` - Complete user journeys
- `tests/Integration/OAuth/` - OAuth flows
- `tests/Integration/Security/` - Security testing
- `tests/Integration/Webhooks/` - Webhook testing
- `tests/Integration/Jobs/` - Background job testing
- `tests/Unit/Services/` - Service logic testing
