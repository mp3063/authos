# OWASP A07 Test Analysis - Authentication Failures Test Suite

## Executive Summary

**Finding**: The security features ARE implemented and working correctly. The OWASP test is skipping tests because it's looking for features in the wrong place - **the security services exist but are NOT integrated into the authentication flow**.

**Impact**: Integration tests pass because they directly call the services. OWASP tests fail because they test real HTTP endpoints where these services aren't wired up.

**Recommendation**: **Integrate security services into the authentication flow** by adding middleware or event listeners.

---

## Detailed Analysis

### 1. Feature Implementation Status

| Feature | Models Exist | Services Exist | Integration Status | Test Location |
|---------|--------------|----------------|-------------------|---------------|
| Brute Force Detection | ✅ SecurityIncident | ✅ IntrusionDetectionService | ❌ Not wired to login | Line 45-75 (OWASP) |
| Account Lockout | ✅ AccountLockout | ✅ AccountLockoutService | ❌ Not wired to login | Line 78-112 (OWASP) |
| Credential Stuffing | ✅ SecurityIncident | ✅ IntrusionDetectionService | ❌ Not wired to login | Line 139-164 (OWASP) |
| IP Blocking | ✅ IpBlocklist | ✅ IpBlocklistService | ❌ Not wired to login | Line 167-192 (OWASP) |
| Failed Login Logging | ✅ FailedLoginAttempt | ✅ IntrusionDetectionService | ❌ Not created on failure | Line 481-499 (OWASP) |
| Password Reset | ❌ No endpoint | ❌ No implementation | ❌ Not implemented | Line 388-411 (OWASP) |
| MFA Recovery Codes | ✅ Endpoint exists | ✅ Implementation exists | ✅ WIRED | Line 451-478 (OWASP) |
| Organization Admin Role | ❌ Role doesn't exist | N/A | ❌ Using different role name | Line 289-331 (OWASP) |

### 2. Why Integration Tests Pass

**Location**: `/Users/sin/PhpstormProjects/MOJE/authos/tests/Integration/Security/`

Integration tests directly instantiate and call the services:

```php
// IntrusionDetectionTest.php (line 69)
$service = app(\App\Services\Security\IntrusionDetectionService::class);
$detected = $service->detectBruteForce('victim@example.com', '192.168.1.99');

// ProgressiveLockoutTest.php (line 84)
$lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

// IpBlockingTest.php (line 75)
$detected = $this->intrusionService->detectBruteForce('victim@example.com', '192.168.1.100');
```

**Why they pass**: Tests manually create `FailedLoginAttempt` records and call services directly, bypassing the real authentication flow.

### 3. Why OWASP Tests Skip/Fail

**Location**: `/Users/sin/PhpstormProjects/MOJE/authos/tests/Security/OwaspA07AuthenticationFailuresTest.php`

OWASP tests make HTTP requests to the login endpoint:

```php
// Line 51-54
$response = $this->postJson('/api/v1/auth/login', [
    'email' => $this->user->email,
    'password' => 'wrongpassword',
]);
```

**Why they skip**: After making failed login attempts, they check if `FailedLoginAttempt` records or `SecurityIncident` records were created. Since the services aren't called during login, no records exist, so tests skip.

### 4. The Missing Integration

**Current Authentication Flow** (`/Users/sin/PhpstormProjects/MOJE/authos/app/Http/Controllers/Api/AuthController.php`):

```php
// Line 125-143
public function login(LoginRequest $request): JsonResponse
{
    $user = User::where('email', $request->email)->first();

    if (! $user || ! Hash::check($request->password, $user->password)) {
        $this->authLogService->logAuthenticationEvent(
            $user ?? new User(['email' => $request->email]),
            'login_failed',
            ['client_id' => $request->client_id],
            $request
        );

        return response()->json([
            'message' => 'Invalid credentials',
            // ...
        ], 401);
    }
    // ... rest of login
}
```

**What's missing**:
- No `FailedLoginAttempt::create()` call
- No `IntrusionDetectionService->detectBruteForce()` call
- No `AccountLockoutService->checkAndApplyLockout()` call
- No `IpBlocklistService->isIpBlocked()` check

### 5. Evidence of Non-Integration

**Finding**: `FailedLoginAttempt` records are ONLY created in tests, never in production code.

```bash
# Search results show only test files create these records:
$ grep -r "FailedLoginAttempt::create" /Users/sin/PhpstormProjects/MOJE/authos/app

# Output:
/Users/sin/PhpstormProjects/MOJE/authos/app/Services/Security/IntrusionDetectionService.php:        FailedLoginAttempt::create([
```

The only production code that creates `FailedLoginAttempt` is inside `IntrusionDetectionService->recordFailedAttempt()` (line not shown), but this method is never called from the login controller.

### 6. Services vs Middleware/Listeners

**No middleware exists** to integrate security checks:
```bash
$ ls app/Http/Middleware/*Security*.php
SecurityHeaders.php    # Only adds HTTP headers
OAuthSecurity.php      # OAuth-specific security

$ ls app/Http/Middleware/*Lockout*.php
# No results

$ ls app/Http/Middleware/*Intrusion*.php
# No results
```

**No event listeners exist** to trigger security checks:
```bash
$ ls app/Listeners/**/*Security*.php
# No results

$ ls app/Listeners/**/*Login*.php
# No results
```

### 7. Password Reset & Organization Admin

**Password Reset**:
```bash
$ herd php artisan route:list --path=api/v1/auth/password
# No routes found
```
- Feature genuinely not implemented
- Test correctly skips (line 388-411)

**Organization Admin Role**:
```bash
$ herd php artisan tinker --execute="echo Spatie\Permission\Models\Role::pluck('name')->toJson()"
# Output: ["System Administrator", "User"]
```
- Role "Organization Admin" doesn't exist
- Different naming convention used ("System Administrator")
- Test correctly skips (line 293-331)

**MFA Recovery Codes**:
```bash
$ herd php artisan route:list --path=api/v1/mfa/recovery
# Routes exist:
POST api/v1/mfa/recovery-codes
POST api/v1/mfa/recovery-codes/regenerate
```
- Feature implemented correctly
- Test may still skip if MFA not set up properly in test

---

## Root Cause Analysis

### The Disconnect

```
┌─────────────────────────────────────────────────────────────┐
│                    INTEGRATION TESTS                         │
│  (100% Pass - Direct Service Calls)                          │
│                                                               │
│  1. Create FailedLoginAttempt manually                       │
│  2. Call service directly                                    │
│  3. Verify incident/lockout created                          │
│                                                               │
│  ✅ Tests pass because services work correctly               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      OWASP TESTS                             │
│  (Skip/Fail - HTTP Endpoint Testing)                         │
│                                                               │
│  1. POST /api/v1/auth/login (wrong password)                 │
│  2. Check if FailedLoginAttempt exists                       │
│  3. Check if SecurityIncident exists                         │
│                                                               │
│  ❌ Tests skip because records never created                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    THE MISSING LINK                          │
│                                                               │
│  AuthController->login()                                     │
│    ❌ Never calls IntrusionDetectionService                  │
│    ❌ Never calls AccountLockoutService                      │
│    ❌ Never creates FailedLoginAttempt                       │
│    ❌ Never checks IpBlocklistService                        │
│                                                               │
│  Services exist but aren't wired to the login flow!          │
└─────────────────────────────────────────────────────────────┘
```

---

## Recommendations

### Option 1: Integrate Services into AuthController (Quick Fix)

**Modify** `/Users/sin/PhpstormProjects/MOJE/authos/app/Http/Controllers/Api/AuthController.php`:

```php
public function login(LoginRequest $request): JsonResponse
{
    // ✅ ADD: Check if IP is blocked
    $ipBlocklistService = app(\App\Services\Security\IpBlocklistService::class);
    if ($ipBlocklistService->isIpBlocked($request->ip())) {
        return response()->json([
            'message' => 'Access denied',
            'error' => 'ip_blocked',
        ], 403);
    }

    // ✅ ADD: Check if account is locked
    $lockoutService = app(\App\Services\Security\AccountLockoutService::class);
    if ($lockoutService->isAccountLocked($request->email)) {
        return response()->json([
            'message' => 'Account temporarily locked',
            'error' => 'account_locked',
        ], 403);
    }

    $user = User::where('email', $request->email)->first();

    if (! $user || ! Hash::check($request->password, $user->password)) {
        // ✅ ADD: Record failed login attempt
        \App\Models\FailedLoginAttempt::create([
            'email' => $request->email,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'attempt_type' => 'password',
            'failure_reason' => 'invalid_credentials',
            'attempted_at' => now(),
        ]);

        // ✅ ADD: Detect intrusion attempts
        $intrusionService = app(\App\Services\Security\IntrusionDetectionService::class);
        $intrusionService->detectBruteForce($request->email, $request->ip());
        $intrusionService->detectCredentialStuffing($request->ip());

        // ✅ ADD: Apply lockout if needed
        $lockoutService->checkAndApplyLockout($request->email, $request->ip());

        $this->authLogService->logAuthenticationEvent(
            $user ?? new User(['email' => $request->email]),
            'login_failed',
            ['client_id' => $request->client_id],
            $request
        );

        return response()->json([
            'message' => 'Invalid credentials',
            'error' => 'invalid_grant',
            'error_description' => 'The provided credentials are incorrect.',
        ], 401);
    }

    // ✅ ADD: Clear failed attempts on successful login
    $lockoutService->clearFailedAttempts($request->email);

    // ... rest of login logic
}
```

**Pros**:
- Quick to implement
- Minimal changes needed
- OWASP tests will pass immediately

**Cons**:
- Bloats controller logic
- Hard to test in isolation
- Couples controller to multiple services

### Option 2: Create Middleware (Better Architecture)

**Create** `/Users/sin/PhpstormProjects/MOJE/authos/app/Http/Middleware/SecurityChecks.php`:

```php
<?php

namespace App\Http\Middleware;

use App\Services\Security\IpBlocklistService;
use App\Services\Security\AccountLockoutService;
use Closure;
use Illuminate\Http\Request;

class SecurityChecks
{
    public function __construct(
        protected IpBlocklistService $ipBlocklistService,
        protected AccountLockoutService $lockoutService
    ) {}

    public function handle(Request $request, Closure $next)
    {
        // Check IP blocklist
        if ($this->ipBlocklistService->isIpBlocked($request->ip())) {
            return response()->json([
                'message' => 'Access denied',
                'error' => 'ip_blocked',
            ], 403);
        }

        // Check account lockout (if email provided)
        if ($request->has('email') &&
            $this->lockoutService->isAccountLocked($request->email)) {
            return response()->json([
                'message' => 'Account temporarily locked',
                'error' => 'account_locked',
            ], 403);
        }

        return $next($request);
    }
}
```

**Register** in `/Users/sin/PhpstormProjects/MOJE/authos/app/Http/Kernel.php`:

```php
protected $middlewareAliases = [
    // ...
    'security.checks' => \App\Http\Middleware\SecurityChecks::class,
];
```

**Apply** to login route in `/Users/sin/PhpstormProjects/MOJE/authos/routes/api.php`:

```php
Route::post('/auth/login', [AuthController::class, 'login'])
    ->middleware('security.checks');
```

**Pros**:
- Clean separation of concerns
- Reusable across multiple endpoints
- Easy to test middleware independently

**Cons**:
- Still need to record failed attempts in controller

### Option 3: Event-Driven Architecture (Best Practice)

**Create Event**: `LoginFailed`

```php
<?php

namespace App\Events\Auth;

use Illuminate\Http\Request;

class LoginFailed
{
    public function __construct(
        public string $email,
        public string $ipAddress,
        public string $userAgent,
        public string $reason
    ) {}
}
```

**Create Listener**: `HandleFailedLoginAttempt`

```php
<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginFailed;
use App\Models\FailedLoginAttempt;
use App\Services\Security\IntrusionDetectionService;
use App\Services\Security\AccountLockoutService;

class HandleFailedLoginAttempt
{
    public function __construct(
        protected IntrusionDetectionService $intrusionService,
        protected AccountLockoutService $lockoutService
    ) {}

    public function handle(LoginFailed $event): void
    {
        // Record failed attempt
        FailedLoginAttempt::create([
            'email' => $event->email,
            'ip_address' => $event->ipAddress,
            'user_agent' => $event->userAgent,
            'attempt_type' => 'password',
            'failure_reason' => $event->reason,
            'attempted_at' => now(),
        ]);

        // Detect intrusion
        $this->intrusionService->detectBruteForce($event->email, $event->ipAddress);
        $this->intrusionService->detectCredentialStuffing($event->ipAddress);

        // Apply lockout if needed
        $this->lockoutService->checkAndApplyLockout($event->email, $event->ipAddress);
    }
}
```

**Modify AuthController**:

```php
if (! $user || ! Hash::check($request->password, $user->password)) {
    // Dispatch event
    event(new \App\Events\Auth\LoginFailed(
        email: $request->email,
        ipAddress: $request->ip(),
        userAgent: $request->userAgent(),
        reason: 'invalid_credentials'
    ));

    // ... existing error response
}
```

**Pros**:
- Best separation of concerns
- Highly testable
- Easy to add more listeners
- Follows Laravel best practices

**Cons**:
- More files to create
- Slightly more complex

---

## Implementation Priority

### High Priority (Required for OWASP Tests to Pass)

1. **Record Failed Login Attempts** - Add `FailedLoginAttempt::create()` to login flow
2. **Check Account Lockout** - Call `AccountLockoutService->isAccountLocked()` before login
3. **Check IP Blocklist** - Call `IpBlocklistService->isIpBlocked()` before login
4. **Trigger Intrusion Detection** - Call detection services on failed login
5. **Apply Lockout** - Call `AccountLockoutService->checkAndApplyLockout()` after failed attempts

### Medium Priority (Nice to Have)

6. **Implement Password Reset** - Create `/api/v1/auth/password/email` and `/api/v1/auth/password/reset` endpoints
7. **Fix Role Naming** - Either create "Organization Admin" role or update test expectations

### Low Priority (Already Working)

8. **MFA Recovery Codes** - Already implemented, test may need adjustment

---

## Test Execution Plan

### Phase 1: Verify Current State

```bash
# Run OWASP tests (will skip)
herd php artisan test tests/Security/OwaspA07AuthenticationFailuresTest.php

# Run integration tests (should pass)
herd php artisan test tests/Integration/Security/
```

### Phase 2: Implement Integration (Choose one option)

- Option 1: Modify AuthController directly
- Option 2: Create middleware + modify controller
- Option 3: Create event/listener system

### Phase 3: Verify Integration

```bash
# Run OWASP tests again (should pass now)
herd php artisan test tests/Security/OwaspA07AuthenticationFailuresTest.php

# Run integration tests (should still pass)
herd php artisan test tests/Integration/Security/
```

---

## Conclusion

**The security features exist and work correctly.** The issue is purely architectural - services are implemented but not integrated into the authentication flow.

**Recommended Solution**: Implement **Option 3 (Event-Driven Architecture)** for best practices, or **Option 1 (Quick Fix)** if time is limited.

**Expected Outcome**: After integration, OWASP tests will stop skipping and should pass, confirming the security features are working end-to-end.
