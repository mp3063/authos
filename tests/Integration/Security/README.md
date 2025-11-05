# Security Integration Tests

This directory contains end-to-end tests for security features and protections.

## Purpose

Test complete security flows including intrusion detection, progressive lockout,
IP blocking, organization boundaries, and security headers.

## What Belongs Here

- **Intrusion Detection Tests** - Testing all 6 detection methods (brute force, credential stuffing, SQL injection, XSS, API abuse, unusual login patterns)
- **Progressive Lockout Tests** - Testing the escalating lockout schedule (5min → 24hrs)
- **Organization Boundary Tests** - Multi-tenant isolation enforcement
- **IP Blocking Tests** - Automatic and manual IP blocking
- **Security Headers Tests** - CSP, HSTS, X-Frame-Options, Permissions-Policy
- **Security Incident Tests** - Incident creation and management

## Test Naming Convention

Tests should use descriptive names that indicate the security scenario:

```php
public function test_brute_force_attack_triggers_progressive_lockout()
public function test_sql_injection_detected_and_blocked()
public function test_user_cannot_access_another_organization_data()
public function test_blocked_ip_cannot_access_any_endpoint()
public function test_csp_headers_present_on_admin_panel()
```

## Required Annotations

All security tests must be tagged with `@group security` and `@group critical`:

```php
/**
 * @test
 * @group security
 * @group critical
 */
public function test_brute_force_attack_triggers_progressive_lockout()
{
    // Test implementation
}
```

## Test Structure

Security tests should follow this pattern:

1. **ARRANGE** - Set up vulnerable scenario
2. **ACT** - Perform security attack/violation
3. **ASSERT** - Verify detection and response
4. **ASSERT** - Verify side effects (incident logging, notifications, blocking)

Example:

```php
public function test_brute_force_attack_triggers_progressive_lockout()
{
    // ARRANGE
    $user = $this->createUser();

    // ACT: Simulate 3 failed login attempts
    $this->simulateFailedLoginAttempts($user->email, 3);

    // ASSERT: User locked for 5 minutes
    $this->assertDatabaseHas('users', [
        'id' => $user->id,
        'locked_until' => now()->addMinutes(5)->toDateTimeString(),
    ]);

    // ASSERT: Security incident created
    $this->assertSecurityIncidentCreated([
        'user_id' => $user->id,
        'type' => 'brute_force',
        'severity' => 'medium',
    ]);

    // ASSERT: Email notification sent
    $this->assertNotificationSentTo($user, AccountLockedNotification::class);
}
```

## Key Assertions

Use these helper methods from IntegrationTestCase:

- `$this->assertSecurityIncidentCreated(['type' => 'brute_force'])`
- `$this->assertNotificationSentTo($user, NotificationClass::class)`
- `$this->assertOrganizationBoundaryEnforced($user, '/api/v1/organizations/999')`
- `$this->assertHasSecurityHeaders()`

## Related Documentation

- Security architecture: See `/app/Http/Middleware/SecurityMiddleware.php`
- Intrusion detection: See `/app/Services/IntrusionDetectionService.php`
- Progressive lockout: See migration for `users.locked_until`
