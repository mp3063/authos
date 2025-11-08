# Event-Driven Security - Quick Start Guide

## 5-Minute Overview

The authentication system uses Laravel events to integrate security measures into the login flow.

## Flow Summary

```
Login Request
    ↓
LoginAttempted Event
    → CheckIpBlocklist (abort if blocked)
    → CheckAccountLockout (abort if locked)
    ↓
Verify Credentials
    ↓
    ├─ FAILED → LoginFailed Event
    │              → RecordFailedLoginAttempt
    │              → TriggerIntrusionDetection
    │                 • Detect brute force
    │                 • Detect credential stuffing
    │                 • Apply progressive lockout
    │                 • Block IP if severe
    │
    └─ SUCCESS → LoginSuccessful Event
                   → RegenerateSession
                      • Clear failed attempts
                      • Unlock expired lockouts
                      • Log success
```

## Key Files

### Events (What Happened)
- `/app/Events/Auth/LoginAttempted.php` - Login attempt started
- `/app/Events/Auth/LoginFailed.php` - Login failed (invalid credentials/inactive)
- `/app/Events/Auth/LoginSuccessful.php` - Login succeeded

### Listeners (What To Do)
- `/app/Listeners/Auth/CheckIpBlocklist.php` - Abort if IP blocked
- `/app/Listeners/Auth/CheckAccountLockout.php` - Abort if account locked
- `/app/Listeners/Auth/RecordFailedLoginAttempt.php` - Store failed attempt
- `/app/Listeners/Auth/TriggerIntrusionDetection.php` - Analyze and respond to attacks
- `/app/Listeners/Auth/RegenerateSession.php` - Clean up after success

### Registration
- `/app/Providers/EventServiceProvider.php` - Event-listener mappings

### Controller
- `/app/Http/Controllers/Api/AuthController.php` - Dispatches events

## Security Services

### IntrusionDetectionService
**Location**: `/app/Services/Security/IntrusionDetectionService.php`

**Detects**:
- Brute force (5 email attempts or 10 IP attempts in 15min)
- Credential stuffing (10 unique emails from IP in 5min)
- SQL injection patterns
- XSS attempts
- API abuse
- Unusual login patterns

**Actions**:
- Creates security incidents
- Auto-blocks IPs on severe attacks
- Works with AccountLockoutService

### AccountLockoutService
**Location**: `/app/Services/Security/AccountLockoutService.php`

**Progressive Schedule**:
- 3 attempts → 5 minutes
- 5 attempts → 15 minutes
- 7 attempts → 30 minutes
- 10 attempts → 1 hour
- 15 attempts → 24 hours

**Features**:
- Email notifications (locked/unlocked)
- Manual admin unlock
- Auto-unlock expired lockouts
- Clear attempts on success

### IpBlocklistService
**Location**: `/app/Services/Security/IpBlocklistService.php`

**Block Types**:
- Temporary (default 24 hours, configurable)
- Permanent

**Features**:
- Cached for performance (5min TTL)
- Manual block/unblock
- Auto-expire temporary blocks
- Track incident count per IP

## Error Responses

### IP Blocked (403)
```json
{
  "message": "Access denied",
  "error": "ip_blocked",
  "error_description": "Your IP address has been blocked due to suspicious activity."
}
```

### Account Locked (403)
```json
{
  "message": "Your account has been temporarily locked...",
  "error": "account_locked",
  "error_description": "Account temporarily locked due to 5 failed login attempts. Duration: 15 minutes.",
  "locked_until": "2024-01-08T14:30:00Z",
  "remaining_minutes": 12
}
```

## Testing

### Run Security Tests
```bash
# All security tests (99 tests, ~9s)
herd php artisan test tests/Integration/Security/

# By category
herd php artisan test tests/Integration/Security/IntrusionDetectionTest.php  # 27 tests
herd php artisan test tests/Integration/Security/IpBlockingTest.php         # 23 tests
herd php artisan test tests/Integration/Security/ProgressiveLockoutTest.php # 20 tests
```

### Example: Test Brute Force Detection
```php
#[Test]
public function brute_force_triggers_lockout(): void
{
    $email = 'test@example.com';

    // Simulate 5 failed attempts
    for ($i = 0; $i < 5; $i++) {
        $this->postJson('/api/auth/login', [
            'email' => $email,
            'password' => 'wrong-password'
        ]);
    }

    // 6th attempt should be blocked
    $response = $this->postJson('/api/auth/login', [
        'email' => $email,
        'password' => 'correct-password'
    ]);

    $response->assertStatus(403);
    $response->assertJson(['error' => 'account_locked']);
}
```

## Admin Operations

### Manually Unlock Account
```php
use App\Services\Security\AccountLockoutService;

$lockoutService = app(AccountLockoutService::class);
$lockoutService->unlockByAdmin('user@example.com', auth()->user());
```

### Manually Block IP
```php
use App\Services\Security\IpBlocklistService;

$ipService = app(IpBlocklistService::class);
$ipService->blockIp(
    ipAddress: '192.168.1.100',
    blockType: 'temporary',
    reason: 'Suspicious activity',
    durationHours: 48,
    blockedBy: auth()->user()
);
```

### Manually Unblock IP
```php
$ipService->unblockIp('192.168.1.100');
```

### Check Security Status
```bash
herd php artisan tinker

# Check if account is locked
AccountLockout::where('email', 'user@example.com')
    ->whereNull('unlocked_at')
    ->exists();

# Check failed attempts in last hour
FailedLoginAttempt::where('email', 'user@example.com')
    ->where('attempted_at', '>=', now()->subHour())
    ->count();

# Check if IP is blocked
IpBlocklist::where('ip_address', '192.168.1.100')
    ->where('is_active', true)
    ->exists();

# Get open security incidents
SecurityIncident::where('status', 'open')
    ->orderBy('detected_at', 'desc')
    ->get();
```

## Configuration

### Thresholds (config/security.php)
```php
'brute_force' => [
    'email_threshold' => env('BRUTE_FORCE_EMAIL_THRESHOLD', 5),
    'ip_threshold' => env('BRUTE_FORCE_IP_THRESHOLD', 10),
],

'credential_stuffing' => [
    'threshold' => env('CREDENTIAL_STUFFING_THRESHOLD', 10),
],

'ip_blocklist' => [
    'default_block_duration_hours' => env('IP_BLOCK_DEFAULT_DURATION_HOURS', 24),
],
```

### Lockout Schedule
Edit `AccountLockoutService::$lockoutSchedule`:
```php
protected array $lockoutSchedule = [
    3 => 5,      // Change duration here
    5 => 15,
    7 => 30,
    10 => 60,
    15 => 1440,
];
```

## Logs

### Security Log Location
```
storage/logs/security.log
```

### Log Levels
- **CRITICAL**: Credential stuffing, SQL injection → IP auto-blocked
- **ALERT**: Brute force attacks
- **WARNING**: Account lockouts, IP blocks
- **INFO**: Successful logins, unlocks

### Example Log Search
```bash
# Recent brute force attacks
grep "Brute force attack detected" storage/logs/security.log | tail -20

# Recent lockouts
grep "Account locked" storage/logs/security.log | tail -20

# Blocked IP attempts
grep "Blocked IP attempted login" storage/logs/security.log | tail -20
```

## Adding New Security Measures

### 1. Create Listener
```php
namespace App\Listeners\Auth;

class MySecurityCheck
{
    public function handle(LoginAttempted $event): void
    {
        // Your security logic
        if ($suspicious) {
            throw new HttpResponseException(
                response()->json(['error' => 'blocked'], 403)
            );
        }
    }
}
```

### 2. Register in EventServiceProvider
```php
LoginAttempted::class => [
    CheckIpBlocklist::class,
    CheckAccountLockout::class,
    MySecurityCheck::class,  // Add here
],
```

### 3. Done!
No controller changes needed - the event system handles it.

## Performance

### Database Indexes
Ensure these indexes exist:
```sql
CREATE INDEX idx_failed_email_attempted ON failed_login_attempts(email, attempted_at);
CREATE INDEX idx_failed_ip_attempted ON failed_login_attempts(ip_address, attempted_at);
CREATE INDEX idx_lockout_email_active ON account_lockouts(email, unlocked_at, unlock_at);
CREATE INDEX idx_ip_active_expires ON ip_blocklist(ip_address, is_active, expires_at);
```

### Caching
- IP blocklist cached for 5 minutes
- Cleared on block/unblock operations
- Configure cache driver in `.env`:
```bash
CACHE_DRIVER=redis  # Recommended for production
```

## Troubleshooting

### User Can't Login
1. Check if account is locked:
```bash
herd php artisan tinker
AccountLockout::where('email', 'user@example.com')->whereNull('unlocked_at')->first();
```

2. Check failed attempts:
```bash
FailedLoginAttempt::where('email', 'user@example.com')
    ->where('attempted_at', '>=', now()->subHour())
    ->get();
```

3. Manually unlock:
```bash
AccountLockout::where('email', 'user@example.com')->update(['unlocked_at' => now()]);
```

### IP Blocked Incorrectly
1. Check block details:
```bash
IpBlocklist::where('ip_address', '192.168.1.100')->where('is_active', true)->first();
```

2. Unblock:
```bash
IpBlocklist::where('ip_address', '192.168.1.100')->update(['is_active' => false]);
```

3. Clear cache:
```bash
herd php artisan cache:forget security:blocked_ips
```

## Security Test Results

**Total**: 99 tests, 287 assertions
**Status**: ✅ 100% passing
**Coverage**:
- Intrusion Detection: 27 tests ✅
- IP Blocking: 23 tests ✅
- Progressive Lockout: 20 tests ✅
- Organization Boundary: 19 tests ✅
- Security Headers: 10 tests ✅

## Support

- Full documentation: `/docs/architecture/event-driven-security.md`
- Service source: `/app/Services/Security/`
- Event source: `/app/Events/Auth/`
- Listener source: `/app/Listeners/Auth/`
- Tests: `/tests/Integration/Security/`
