# Laravel Best Practices Alignment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the AuthOS application into full alignment with Laravel best practices across database performance, security, job configuration, caching, HTTP client patterns, and Eloquent conventions.

**Architecture:** Changes are organized in 4 phases (P0-P3) by descending impact. Each task is self-contained and independently committable. Phase 0 fixes production-risk issues (race conditions, data leaks). Phases 1-3 improve robustness, maintainability, and conventions. No architectural rewrites — surgical fixes to existing code.

**Tech Stack:** PHP 8.4, Laravel 12, PHPUnit 11, PostgreSQL, Redis/Database cache

---

## Phase 0 — Critical Production Fixes

### Task 1: Fix Queue `retry_after` to Exceed Max Job Timeout

**Files:**
- Modify: `config/queue.php:42,50,70`

**Context:** The `retry_after` value (90s) is lower than multiple job timeouts (300-600s). This causes Laravel to re-dispatch jobs while they're still running, creating duplicate execution.

- [ ] **Step 1: Update retry_after for database connection**

In `config/queue.php`, change line 42:

```php
// Before:
'retry_after' => (int) env('DB_QUEUE_RETRY_AFTER', 90),

// After:
'retry_after' => (int) env('DB_QUEUE_RETRY_AFTER', 660),
```

- [ ] **Step 2: Update retry_after for redis connection**

In `config/queue.php`, change line 70:

```php
// Before:
'retry_after' => (int) env('REDIS_QUEUE_RETRY_AFTER', 90),

// After:
'retry_after' => (int) env('REDIS_QUEUE_RETRY_AFTER', 660),
```

- [ ] **Step 3: Update retry_after for beanstalkd connection**

In `config/queue.php`, change line 50:

```php
// Before:
'retry_after' => (int) env('BEANSTALKD_QUEUE_RETRY_AFTER', 90),

// After:
'retry_after' => (int) env('BEANSTALKD_QUEUE_RETRY_AFTER', 660),
```

- [ ] **Step 4: Verify no tests depend on the old value**

Run: `herd php artisan test --filter=Queue`
Expected: All existing tests pass (retry_after is a config value, unlikely to be tested directly)

- [ ] **Step 5: Commit**

```bash
git add config/queue.php
git commit -m "fix: increase retry_after to 660s to exceed max job timeout (600s)

Jobs with 600s timeouts were being re-dispatched while still running,
causing duplicate execution. retry_after must always exceed the longest
job timeout."
```

---

### Task 2: Add `ShouldDispatchAfterCommit` to All Events

**Files:**
- Modify: All 19 event files in `app/Events/` (excluding `app/Events/Auth/` subdirectory which contains different event pattern)

**Context:** Events are dispatched inside DB transactions (e.g., user creation, webhook triggers). Without `ShouldDispatchAfterCommit`, listeners (especially webhook delivery jobs) may process before the transaction commits, reading stale/missing data.

- [ ] **Step 1: Update UserCreatedEvent**

In `app/Events/UserCreatedEvent.php`, add the interface:

```php
// Before:
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UserCreatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

// After:
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UserCreatedEvent implements ShouldDispatchAfterCommit
{
    use Dispatchable, InteractsWithSockets, SerializesModels;
```

- [ ] **Step 2: Apply the same pattern to all remaining events**

Apply the identical change (add `use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;` import and `implements ShouldDispatchAfterCommit` to class declaration) to each of these files:

```
app/Events/UserUpdatedEvent.php
app/Events/UserDeletedEvent.php
app/Events/AuthLoginEvent.php
app/Events/AuthFailedEvent.php
app/Events/MfaEnabledEvent.php
app/Events/MfaDisabledEvent.php
app/Events/ApplicationCreatedEvent.php
app/Events/ApplicationUpdatedEvent.php
app/Events/ApplicationDeletedEvent.php
app/Events/OrganizationSettingsChangedEvent.php
app/Events/OrganizationUpdatedEvent.php
app/Events/RoleCreatedEvent.php
app/Events/RoleUpdatedEvent.php
app/Events/RoleDeletedEvent.php
app/Events/WebhookCreatedEvent.php
app/Events/WebhookUpdatedEvent.php
app/Events/WebhookDeletedEvent.php
app/Events/DomainVerifiedEvent.php
```

Do NOT modify the files in `app/Events/Auth/` subdirectory — those follow a different pattern (LoginAttempted, LoginFailed, LoginSuccessful).

- [ ] **Step 3: Run webhook and event tests**

Run: `herd php artisan test tests/Integration/Webhooks/`
Expected: All 62 tests pass

Run: `herd php artisan test tests/Integration/Models/`
Expected: All 40 tests pass

- [ ] **Step 4: Commit**

```bash
git add app/Events/
git commit -m "fix: add ShouldDispatchAfterCommit to all domain events

Prevents webhook delivery jobs and listeners from processing before
the database transaction commits, which could cause them to read
stale or missing data."
```

---

### Task 3: Fix N+1 Query in ApplicationController::tokens()

**Files:**
- Modify: `app/Http/Controllers/Api/ApplicationController.php:436-460`
- Test: `tests/Integration/Applications/ApplicationTokensTest.php`

**Context:** Line 443 calls `User::find($token->user_id)` inside a `->map()` loop over tokens, producing 1+N queries.

- [ ] **Step 1: Write a test that verifies tokens endpoint returns user data**

Check if `tests/Integration/Applications/ApplicationTokensTest.php` already covers the tokens endpoint. If it does, skip to Step 2. If not, add:

```php
#[Test]
public function it_returns_tokens_with_user_data(): void
{
    $response = $this->actingAs($this->admin, 'api')
        ->getJson("/api/v1/applications/{$this->application->id}/tokens");

    $response->assertOk();
}
```

- [ ] **Step 2: Fix the N+1 by eager-loading users**

In `app/Http/Controllers/Api/ApplicationController.php`, replace the tokens method body (around lines 436-460):

```php
// Before:
$tokens = Token::where('client_id', $application->passport_client_id)
    ->where('revoked', false)
    ->where('expires_at', '>', now())
    ->get();

return response()->json([
    'data' => $tokens->map(function ($token) {
        // Load user manually to avoid relationship issues
        $user = User::find($token->user_id);

        return [
            'id' => $token->id,
            'name' => $token->name,
            'scopes' => $token->scopes,
            'user' => $user ? [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ] : null,
            'created_at' => $token->created_at,
            'expires_at' => $token->expires_at,
        ];
    }),
]);

// After:
$tokens = Token::where('client_id', $application->passport_client_id)
    ->where('revoked', false)
    ->where('expires_at', '>', now())
    ->get();

$userIds = $tokens->pluck('user_id')->filter()->unique()->values();
$users = User::whereIn('id', $userIds)->get()->keyBy('id');

return response()->json([
    'data' => $tokens->map(function ($token) use ($users) {
        $user = $users->get($token->user_id);

        return [
            'id' => $token->id,
            'name' => $token->name,
            'scopes' => $token->scopes,
            'user' => $user ? [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ] : null,
            'created_at' => $token->created_at,
            'expires_at' => $token->expires_at,
        ];
    }),
]);
```

- [ ] **Step 3: Run token tests**

Run: `herd php artisan test tests/Integration/Applications/ApplicationTokensTest.php`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add app/Http/Controllers/Api/ApplicationController.php
git commit -m "fix: resolve N+1 query in ApplicationController::tokens()

Batch-load all users for tokens in 2 queries instead of 1+N."
```

---

### Task 4: Fix N+1 in ApplicationController::analytics() — In-Memory Filtering

**Files:**
- Modify: `app/Http/Controllers/Api/ApplicationController.php:549-570`

**Context:** Lines 549-551 load ALL AuthenticationLog records with `->get()`, then filter in PHP. This loads potentially thousands of records into memory when database-level aggregation would be far more efficient.

- [ ] **Step 1: Replace in-memory filtering with database queries**

In `app/Http/Controllers/Api/ApplicationController.php`, replace the analytics query block (around lines 549-562):

```php
// Before:
$authLogs = AuthenticationLog::where('application_id', $application->id)
    ->where('created_at', '>=', $startDate)
    ->get();

$successfulLogins = $authLogs->where('event', 'login_success')->count();
$failedLogins = $authLogs->where('event', 'login_failed')->count();
$uniqueUsers = $authLogs->pluck('user_id')->unique()->count();

// After:
$baseQuery = AuthenticationLog::where('application_id', $application->id)
    ->where('created_at', '>=', $startDate);

$successfulLogins = (clone $baseQuery)->where('event', 'login_success')->count();
$failedLogins = (clone $baseQuery)->where('event', 'login_failed')->count();
$uniqueUsers = (clone $baseQuery)->distinct('user_id')->count('user_id');
```

- [ ] **Step 2: Run application tests**

Run: `herd php artisan test tests/Integration/Applications/ApplicationAnalyticsTest.php`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add app/Http/Controllers/Api/ApplicationController.php
git commit -m "fix: replace in-memory log filtering with database queries in analytics

Avoids loading entire AuthenticationLog table into memory. Uses
database-level COUNT and DISTINCT instead."
```

---

### Task 5: Fix N+1 in Bulk User Operations

**Files:**
- Modify: `app/Http/Controllers/Api/UserController.php:340-370,405-425`

**Context:** `bulkGrantApplicationAccess()` and `bulkRevokeApplicationAccess()` both call `User::findOrFail($userId)` inside a foreach loop (up to 100 iterations = up to 100 queries).

- [ ] **Step 1: Fix bulkGrantApplicationAccess (lines 357-370)**

In `app/Http/Controllers/Api/UserController.php`, replace the loop:

```php
// Before:
foreach ($request->user_ids as $userId) {
    $user = User::findOrFail($userId);

    // Verify user belongs to same organization as application
    if ($user->organization_id !== $application->organization_id) {
        continue;
    }

    $this->userManagementService->grantApplicationAccess(
        $user,
        $request->application_id,
        $request->permissions,
        $currentUser->id
    );
}

// After:
$users = User::whereIn('id', $request->user_ids)
    ->where('organization_id', $application->organization_id)
    ->get();

foreach ($users as $user) {
    $this->userManagementService->grantApplicationAccess(
        $user,
        $request->application_id,
        $request->permissions,
        $currentUser->id
    );
}
```

- [ ] **Step 2: Fix bulkRevokeApplicationAccess (lines 418-424)**

```php
// Before:
foreach ($request->user_ids as $userId) {
    $user = User::findOrFail($userId);
    $this->userManagementService->revokeApplicationAccess(
        $user,
        (int) $applicationId,
        $currentUser->id
    );
}

// After:
$users = User::whereIn('id', $request->user_ids)->get();

foreach ($users as $user) {
    $this->userManagementService->revokeApplicationAccess(
        $user,
        (int) $applicationId,
        $currentUser->id
    );
}
```

- [ ] **Step 3: Run user tests**

Run: `herd php artisan test tests/Integration/Users/`
Expected: All 53 tests pass

- [ ] **Step 4: Commit**

```bash
git add app/Http/Controllers/Api/UserController.php
git commit -m "fix: batch-load users in bulk grant/revoke operations

Replaces individual User::findOrFail() calls in loop (up to 100
queries) with single whereIn query."
```

---

### Task 6: Fix OrganizationCrudController::show() Count Queries

**Files:**
- Modify: `app/Http/Controllers/Api/Organizations/OrganizationCrudController.php:148-158`

**Context:** Two separate count queries (`User::where(...)->count()` and `Application::where(...)->count()`) instead of using `withCount()`.

- [ ] **Step 1: Replace manual counts with withCount()**

```php
// Before:
$organization = Organization::findOrFail($id);

// Set manual counts for resource compatibility (using separate queries)
$organization->setAttribute('users_count', User::where('organization_id', $organization->id)->count());
$organization->setAttribute('applications_count', Application::where('organization_id', $organization->id)->count());

// After:
$organization = Organization::withCount(['organizationUsers as users_count', 'applications as applications_count'])
    ->findOrFail($id);
```

- [ ] **Step 2: Run organization tests**

Run: `herd php artisan test tests/Integration/Organizations/OrganizationCrudTest.php`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add app/Http/Controllers/Api/Organizations/OrganizationCrudController.php
git commit -m "fix: use withCount() instead of separate count queries in org show

Reduces 3 queries to 1 by using Eloquent withCount()."
```

---

### Task 7: Replace `Cache::flush()` with Targeted Invalidation

**Files:**
- Modify: `app/Http/Controllers/Api/Traits/CacheableResponse.php:99-109`

**Context:** `Cache::flush()` on line 104 wipes the ENTIRE cache store — sessions, rate limiters, everything. This is a production risk.

- [ ] **Step 1: Replace flush with pattern-based invalidation**

In `app/Http/Controllers/Api/Traits/CacheableResponse.php`, replace the `invalidateCache` method:

```php
// Before:
protected function invalidateCache(string $pattern): void
{
    // This would require a more sophisticated cache invalidation system
    // For now, we'll use cache tags if available
    try {
        Cache::flush(); // In production, this should be more targeted
    } catch (Exception $e) {
        // Log error but don't fail the request
        logger()->warning('Failed to invalidate cache: '.$e->getMessage());
    }
}

// After:
protected function invalidateCache(string $pattern): void
{
    try {
        $store = Cache::getStore();
        $prefix = config('cache.prefix') ? config('cache.prefix').':' : '';

        if (method_exists($store, 'keys')) {
            $keys = $store->keys($prefix.$pattern);

            foreach ($keys as $key) {
                $unprefixedKey = $prefix ? str_replace($prefix, '', $key) : $key;
                Cache::forget($unprefixedKey);
            }
        }
    } catch (\Exception $e) {
        logger()->warning('Failed to invalidate cache: '.$e->getMessage());
    }
}
```

- [ ] **Step 2: Run cache tests**

Run: `herd php artisan test tests/Integration/Cache/`
Expected: All 28 tests pass

- [ ] **Step 3: Commit**

```bash
git add app/Http/Controllers/Api/Traits/CacheableResponse.php
git commit -m "fix: replace Cache::flush() with targeted pattern invalidation

Cache::flush() was wiping the entire cache store including sessions
and rate limiters. Now only invalidates keys matching the given pattern."
```

---

## Phase 1 — High Priority Improvements

### Task 8: Add `Model::preventLazyLoading()` in Development

**Files:**
- Modify: `app/Providers/AppServiceProvider.php:51-55`

- [ ] **Step 1: Add preventLazyLoading to boot method**

In `app/Providers/AppServiceProvider.php`, add at the start of the `boot()` method (after line 52):

```php
public function boot(): void
{
    Model::preventLazyLoading(! app()->isProduction());
```

Add the import at the top of the file:

```php
use Illuminate\Database\Eloquent\Model;
```

- [ ] **Step 2: Run full test suite to find any lazy loading violations**

Run: `herd php artisan test tests/Integration/ 2>&1 | head -100`

If tests fail with `Attempted to lazy load` errors, those are real N+1 issues that should be fixed with `->with()` eager loading. Note them for follow-up but don't disable `preventLazyLoading` to make tests pass.

- [ ] **Step 3: Commit**

```bash
git add app/Providers/AppServiceProvider.php
git commit -m "feat: enable preventLazyLoading in non-production environments

Surfaces N+1 query issues during development and testing."
```

---

### Task 9: Add Exponential Backoff to All Jobs

**Files:**
- Modify: All 11 job files in `app/Jobs/`

**Context:** Only `SyncLdapUsersJob` has backoff (single value: 60). All others retry immediately, which can overwhelm external services and databases.

- [ ] **Step 1: Add backoff to ProcessBulkExportJob**

In `app/Jobs/ProcessBulkExportJob.php`, add after `$tries`:

```php
public int $timeout = 600;

public int $tries = 3;

/** @var int[] */
public array $backoff = [30, 120, 300];
```

- [ ] **Step 2: Add backoff to ProcessBulkImportJob**

In `app/Jobs/ProcessBulkImportJob.php`, add after `$tries`:

```php
public int $timeout = 600;

public int $tries = 3;

/** @var int[] */
public array $backoff = [30, 120, 300];
```

- [ ] **Step 3: Add backoff to ExportUsersJob**

In `app/Jobs/ExportUsersJob.php`, add after `$tries`:

```php
public int $timeout = 600;

public int $tries = 3;

/** @var int[] */
public array $backoff = [30, 120, 300];
```

- [ ] **Step 4: Add backoff to ProcessAuditExportJob**

In `app/Jobs/ProcessAuditExportJob.php`, add after `$tries`:

```php
public int $timeout = 600;

public int $tries = 2;

/** @var int[] */
public array $backoff = [60, 300];
```

- [ ] **Step 5: Add backoff to GenerateComplianceReportJob**

In `app/Jobs/GenerateComplianceReportJob.php`, add after `$tries`:

```php
public int $timeout = 300;

public int $tries = 2;

/** @var int[] */
public array $backoff = [60, 300];
```

- [ ] **Step 6: Update SyncLdapUsersJob to exponential backoff**

In `app/Jobs/SyncLdapUsersJob.php`, change `$backoff`:

```php
// Before:
public int $backoff = 60;

// After:
/** @var int[] */
public array $backoff = [60, 180, 300];
```

- [ ] **Step 7: Add backoff and timeout to DeliverWebhookJob**

In `app/Jobs/DeliverWebhookJob.php`, add after existing properties:

```php
public int $tries = 1;

public int $maxExceptions = 3;

public int $timeout = 60;

/** @var int[] */
public array $backoff = [10, 30, 60];
```

- [ ] **Step 8: Add timeout and backoff to RetryWebhookDeliveryJob**

In `app/Jobs/RetryWebhookDeliveryJob.php`, add after `$timeout`:

```php
public int $tries = 1;

public int $timeout = 60;

/** @var int[] */
public array $backoff = [30, 60];
```

- [ ] **Step 9: Add timeout and backoff to ProcessDeadLetterWebhookJob**

In `app/Jobs/ProcessDeadLetterWebhookJob.php`, add after `$tries`:

```php
public int $tries = 1;

public int $timeout = 120;

/** @var int[] */
public array $backoff = [30, 60];
```

- [ ] **Step 10: Add timeout, tries, and backoff to ProcessAuth0MigrationJob**

In `app/Jobs/ProcessAuth0MigrationJob.php`, add after `use SerializesModels;`:

```php
public int $timeout = 600;

public int $tries = 3;

/** @var int[] */
public array $backoff = [60, 180, 300];
```

- [ ] **Step 11: Add timeout, tries, and backoff to ProcessOktaMigrationJob**

In `app/Jobs/ProcessOktaMigrationJob.php`, add after `use SerializesModels;`:

```php
public int $timeout = 600;

public int $tries = 3;

/** @var int[] */
public array $backoff = [60, 180, 300];
```

- [ ] **Step 12: Run job tests**

Run: `herd php artisan test tests/Integration/Jobs/`
Expected: All 50 tests pass

- [ ] **Step 13: Commit**

```bash
git add app/Jobs/
git commit -m "feat: add exponential backoff to all jobs

Prevents retry storms when external services or databases are under
load. Each job now has progressive delays between retry attempts."
```

---

### Task 10: Fix `$request->all()` in ProfileController::updatePreferences

**Files:**
- Modify: `app/Http/Controllers/Api/ProfileController.php:232`

**Context:** After validation, `$request->all()` merges ALL request data (including unvalidated fields) into preferences. An attacker could inject arbitrary keys.

- [ ] **Step 1: Replace $request->all() with $request->only()**

In `app/Http/Controllers/Api/ProfileController.php`, change line 232:

```php
// Before:
$preferences = array_merge($profile['preferences'] ?? [], $request->all());

// After:
$validatedKeys = ['timezone', 'language', 'theme', 'date_format', 'time_format', 'email_notifications', 'security_alerts', 'marketing_emails'];
$preferences = array_merge($profile['preferences'] ?? [], $request->only($validatedKeys));
```

- [ ] **Step 2: Run profile tests**

Run: `herd php artisan test tests/Integration/Profile/ProfileManagementTest.php`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add app/Http/Controllers/Api/ProfileController.php
git commit -m "fix: filter request data in updatePreferences to validated keys only

$request->all() was allowing arbitrary keys to be injected into
user preferences. Now only accepts the validated preference fields."
```

---

### Task 11: Add `connectTimeout()` and `retry()` to HTTP Clients

**Files:**
- Modify: `app/Services/Auth0/Auth0Client.php:61-73,83-97,105-117`
- Modify: `app/Services/Okta/OktaClient.php:18-25`
- Modify: `app/Services/WebhookDeliveryService.php:91`

- [ ] **Step 1: Add connectTimeout and retry to Auth0Client::get()**

In `app/Services/Auth0/Auth0Client.php`, update the `get()` method:

```php
// Before:
$response = Http::withHeaders([
    'Authorization' => "Bearer {$this->token}",
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
])->timeout(60)->get("https://{$this->domain}/api/v2/{$endpoint}", $query);

// After:
$response = Http::withHeaders([
    'Authorization' => "Bearer {$this->token}",
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
])
    ->connectTimeout(10)
    ->timeout(60)
    ->retry(3, 500, throw: false)
    ->get("https://{$this->domain}/api/v2/{$endpoint}", $query);
```

- [ ] **Step 2: Apply same pattern to Auth0Client::post()**

Update the `post()` method (around line 89) with the same `connectTimeout(10)` and `retry(3, 500, throw: false)`.

- [ ] **Step 3: Apply same pattern to Auth0Client::testConnection()**

Update the `testConnection()` method (around line 107) with `connectTimeout(10)` and `retry(2, 1000, throw: false)`.

- [ ] **Step 4: Add connectTimeout to OktaClient constructor**

In `app/Services/Okta/OktaClient.php`, update the constructor:

```php
// Before:
$this->http = Http::baseUrl("https://{$this->domain}/api/v1")
    ->withHeaders([
        'Authorization' => "SSWS {$this->apiToken}",
        'Accept' => 'application/json',
        'Content-Type' => 'application/json',
    ])
    ->timeout(30);

// After:
$this->http = Http::baseUrl("https://{$this->domain}/api/v1")
    ->withHeaders([
        'Authorization' => "SSWS {$this->apiToken}",
        'Accept' => 'application/json',
        'Content-Type' => 'application/json',
    ])
    ->connectTimeout(10)
    ->timeout(30)
    ->retry(3, 500, throw: false);
```

- [ ] **Step 5: Add connectTimeout to WebhookDeliveryService**

In `app/Services/WebhookDeliveryService.php`, update line 91:

```php
// Before:
$response = Http::timeout($webhook->timeout_seconds)
    ->withHeaders($headers)
    ->post($webhook->url, $delivery->payload);

// After:
$response = Http::connectTimeout(5)
    ->timeout($webhook->timeout_seconds)
    ->withHeaders($headers)
    ->post($webhook->url, $delivery->payload);
```

Note: Do NOT add `retry()` to webhook delivery — the retry logic is handled at the job level with `RetryWebhookDeliveryJob`.

- [ ] **Step 6: Run relevant tests**

Run: `herd php artisan test tests/Integration/Jobs/ProcessAuth0MigrationJobTest.php`
Run: `herd php artisan test tests/Integration/Webhooks/WebhookDeliveryFlowTest.php`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/Services/Auth0/Auth0Client.php app/Services/Okta/OktaClient.php app/Services/WebhookDeliveryService.php
git commit -m "feat: add connectTimeout and retry to HTTP clients

Auth0/Okta clients now retry transient failures with 500ms backoff.
Webhook delivery gets a 5s connect timeout to fail fast on unreachable hosts."
```

---

### Task 12: Add Safeguards to Scheduled Tasks

**Files:**
- Modify: `routes/console.php`

- [ ] **Step 1: Add withoutOverlapping and onOneServer**

In `routes/console.php`, replace line 11:

```php
// Before:
Schedule::command('invitations:cleanup-expired')->daily();

// After:
Schedule::command('invitations:cleanup-expired')
    ->daily()
    ->withoutOverlapping()
    ->onOneServer()
    ->runInBackground();
```

- [ ] **Step 2: Commit**

```bash
git add routes/console.php
git commit -m "feat: add scheduling safeguards to invitation cleanup

Prevents overlapping runs and ensures single-server execution
in multi-server deployments."
```

---

## Phase 2 — Moderate Improvements

### Task 13: Migrate `$casts` Property to `casts()` Method on All Models

**Files:**
- Modify: 18 model files in `app/Models/`

**Context:** Laravel 12 convention prefers the `casts()` method over the `$casts` property. The method approach enables dynamic cast resolution and aligns with the framework direction.

- [ ] **Step 1: Update Application model**

In `app/Models/Application.php`, replace:

```php
// Before:
protected $casts = [
    'redirect_uris' => 'array',
    'allowed_origins' => 'array',
    'allowed_grant_types' => 'array',
    'scopes' => 'array',
    'settings' => 'array',
    'is_active' => 'boolean',
];

// After:
protected function casts(): array
{
    return [
        'redirect_uris' => 'array',
        'allowed_origins' => 'array',
        'allowed_grant_types' => 'array',
        'scopes' => 'array',
        'settings' => 'array',
        'is_active' => 'boolean',
    ];
}
```

- [ ] **Step 2: Apply same conversion to Organization model**

In `app/Models/Organization.php`, convert `protected $casts` to `protected function casts(): array`.

- [ ] **Step 3: Apply to remaining 16 models**

Convert `$casts` property to `casts()` method in each of:

```
app/Models/Webhook.php
app/Models/BulkImportJob.php
app/Models/AuthenticationLog.php
app/Models/WebhookDelivery.php
app/Models/MigrationJob.php
app/Models/IpBlocklist.php
app/Models/FailedLoginAttempt.php
app/Models/AccountLockout.php
app/Models/SecurityIncident.php
app/Models/Invitation.php
app/Models/SSOSession.php
app/Models/SSOConfiguration.php
app/Models/CustomRole.php
app/Models/ApplicationGroup.php
app/Models/WebhookEvent.php
app/Models/UserApplication.php
```

The pattern is always the same: change `protected $casts = [...]` to `protected function casts(): array { return [...]; }`.

- [ ] **Step 4: Run model tests**

Run: `herd php artisan test tests/Integration/Models/`
Expected: All 40 tests pass

Run: `herd php artisan test tests/Unit/`
Expected: All unit tests pass

- [ ] **Step 5: Commit**

```bash
git add app/Models/
git commit -m "refactor: migrate \$casts property to casts() method on all models

Aligns with Laravel 12 convention. The method approach enables
dynamic cast resolution and is the recommended pattern going forward."
```

---

### Task 14: Add `Cache::lock()` to Cache Warming Operations

**Files:**
- Modify: `app/Services/CacheWarmingService.php:38-71`

**Context:** Concurrent cache warming requests (e.g., from multiple web workers or scheduled tasks) can execute simultaneously, wasting resources on duplicate computation.

- [ ] **Step 1: Add lock to warmOrganizationCaches**

In `app/Services/CacheWarmingService.php`, wrap the `warmOrganizationCaches` method body:

```php
// Before:
public function warmOrganizationCaches(): int
{
    $count = 0;
    $ttl = config('performance.cache.ttl.organization_settings', 1800);

    Organization::chunk(100, function ($organizations) use (&$count, $ttl) {
        // ... cache operations
    });

    return $count;
}

// After:
public function warmOrganizationCaches(): int
{
    $lock = Cache::lock('cache-warming:organizations', 120);

    if (! $lock->get()) {
        Log::info('Organization cache warming already in progress, skipping');

        return 0;
    }

    try {
        $count = 0;
        $ttl = config('performance.cache.ttl.organization_settings', 1800);

        Organization::chunk(100, function ($organizations) use (&$count, $ttl) {
            foreach ($organizations as $org) {
                Cache::remember(
                    "org:settings:{$org->id}",
                    $ttl,
                    fn () => $org->settings ?? []
                );

                Cache::remember(
                    "org:user_count:{$org->id}",
                    $ttl,
                    fn () => $org->organizationUsers()->count()
                );

                Cache::remember(
                    "org:app_count:{$org->id}",
                    $ttl,
                    fn () => $org->applications()->count()
                );

                $count++;
            }
        });

        return $count;
    } finally {
        $lock->release();
    }
}
```

- [ ] **Step 2: Run cache tests**

Run: `herd php artisan test tests/Integration/Cache/`
Expected: All 28 tests pass

- [ ] **Step 3: Commit**

```bash
git add app/Services/CacheWarmingService.php
git commit -m "feat: add cache lock to prevent concurrent warming operations

Uses Cache::lock() with 120s TTL to prevent duplicate computation
when multiple processes attempt to warm caches simultaneously."
```

---

## Phase 3 — Convention Alignment (Optional)

These tasks improve code consistency but have lower production impact. They can be done incrementally.

### Task 15: Replace Hardcoded Magic Strings with Constants

**Files:**
- Create: `app/Enums/UserRole.php`
- Create: `app/Enums/InvitationStatus.php`
- Modify: `app/Http/Controllers/Api/UserController.php` (references to 'Super Admin', 'super-admin')
- Modify: `app/Http/Controllers/Api/InvitationController.php` (references to 'pending', 'expired', 'accepted')

- [ ] **Step 1: Create UserRole enum**

Run: `herd php artisan make:enum UserRole --no-interaction`

If the command doesn't exist, create manually:

```php
<?php

namespace App\Enums;

enum UserRole: string
{
    case SuperAdmin = 'super-admin';
    case OrganizationOwner = 'organization-owner';
    case OrganizationAdmin = 'organization-admin';
    case User = 'user';

    public function label(): string
    {
        return match ($this) {
            self::SuperAdmin => 'Super Admin',
            self::OrganizationOwner => 'Organization Owner',
            self::OrganizationAdmin => 'Organization Admin',
            self::User => 'User',
        };
    }
}
```

- [ ] **Step 2: Create InvitationStatus enum**

```php
<?php

namespace App\Enums;

enum InvitationStatus: string
{
    case Pending = 'pending';
    case Accepted = 'accepted';
    case Expired = 'expired';
    case Cancelled = 'cancelled';
}
```

Check if this enum already exists in the codebase first — if so, just use the existing one.

- [ ] **Step 3: Replace magic strings in UserController**

Search for `'Super Admin'` and `'super-admin'` in `app/Http/Controllers/Api/UserController.php` and replace with `UserRole::SuperAdmin->label()` and `UserRole::SuperAdmin->value` respectively.

- [ ] **Step 4: Replace magic strings in InvitationController**

Search for `'pending'`, `'expired'`, `'accepted'` in `app/Http/Controllers/Api/InvitationController.php` and replace with `InvitationStatus::Pending->value` etc.

- [ ] **Step 5: Run affected tests**

Run: `herd php artisan test tests/Integration/Users/`
Run: `herd php artisan test tests/Integration/Organizations/OrganizationInvitationsTest.php`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/Enums/ app/Http/Controllers/Api/UserController.php app/Http/Controllers/Api/InvitationController.php
git commit -m "refactor: replace magic strings with enums for roles and invitation statuses

Introduces UserRole and InvitationStatus enums to centralize
string constants and improve type safety."
```

---

### Task 16: Standardize Auth0Client Error Handling

**Files:**
- Modify: `app/Services/Auth0/Auth0Client.php:158-174`

**Context:** `handleResponse()` manually checks `$statusCode >= 400` instead of using Laravel's `->throw()` pattern. The OktaClient already uses `->throw()` consistently.

- [ ] **Step 1: Refactor to use throw()**

In `app/Services/Auth0/Auth0Client.php`, update the `get()` and `post()` methods to use `->throw()` and remove the manual `handleResponse()`:

```php
// In get() method, replace:
$response = Http::withHeaders([...])
    ->connectTimeout(10)
    ->timeout(60)
    ->retry(3, 500, throw: false)
    ->get("https://{$this->domain}/api/v2/{$endpoint}", $query);

return $this->handleResponse($response);

// With:
$response = Http::withHeaders([...])
    ->connectTimeout(10)
    ->timeout(60)
    ->retry(3, 500)
    ->get("https://{$this->domain}/api/v2/{$endpoint}", $query);

$response->throw();

return $response->json() ?? [];
```

Apply same pattern to `post()` and `testConnection()` methods.

Then remove the `handleResponse()` private method entirely (lines 158-174).

- [ ] **Step 2: Update exception handling in callers**

Check `ProcessAuth0MigrationJob.php` and any other Auth0Client callers — they may need to catch `RequestException` instead of `Auth0ApiException`. Verify by running tests.

- [ ] **Step 3: Run migration tests**

Run: `herd php artisan test tests/Integration/Jobs/ProcessAuth0MigrationJobTest.php`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add app/Services/Auth0/Auth0Client.php
git commit -m "refactor: standardize Auth0Client error handling to use throw()

Aligns with OktaClient pattern and Laravel HTTP client best practices.
Removes manual status code checking in favor of throw()."
```

---

## Summary

| Phase | Tasks | Estimated Time | Impact |
|-------|-------|---------------|--------|
| P0 — Critical | Tasks 1-7 | ~3 hours | Fixes race conditions, data leaks, N+1 queries |
| P1 — High | Tasks 8-12 | ~2.5 hours | Adds resilience, dev safeguards, connection handling |
| P2 — Moderate | Tasks 13-14 | ~1.5 hours | Convention alignment, concurrent safety |
| P3 — Optional | Tasks 15-16 | ~1.5 hours | Code clarity, consistency |
| **Total** | **16 tasks** | **~8.5 hours** | |

### Execution Order

Tasks within each phase are independent and can be parallelized using subagent-driven development. However, **Task 8 (preventLazyLoading)** may surface additional N+1 issues beyond those fixed in Tasks 3-6 — run it after those fixes.

### Not Included in This Plan

The following audit findings were excluded because they require larger architectural changes that warrant their own dedicated plans:

- **Extract controller logic into Action classes** — affects 3 controllers with 800+ lines each. Needs its own decomposition plan.
- **Convert inline validation to Form Requests** — affects 6+ controllers. Should be done controller-by-controller with dedicated testing.
- **Implement route model binding + apiResource()** — requires route restructuring and test updates. Warrants its own plan.
- **Upgrade cache keys to Cache::flexible()** — needs profiling to identify high-traffic keys first.
- **Add RateLimited middleware to external API jobs** — requires defining rate limit configurations per external service.

These should be planned as separate follow-up initiatives after Phase 0-1 is complete.
