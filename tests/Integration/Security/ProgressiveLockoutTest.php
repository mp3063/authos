<?php

namespace Tests\Integration\Security;

use App\Models\AccountLockout;
use App\Models\FailedLoginAttempt;
use App\Models\User;
use App\Notifications\AccountLockedNotification;
use App\Notifications\AccountUnlockedNotification;
use App\Services\Security\AccountLockoutService;
use Illuminate\Support\Facades\Notification;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Progressive Account Lockout System
 *
 * Tests the 5-tier progressive lockout schedule:
 * - 3 attempts → 5 min lockout
 * - 5 attempts → 15 min lockout
 * - 7 attempts → 30 min lockout
 * - 10 attempts → 1 hour lockout
 * - 15 attempts → 24 hour lockout
 *
 * Verifies:
 * - Lockout duration progression
 * - AccountLockedNotification sent at each stage
 * - AccountUnlockedNotification sent on unlock
 * - Auto-unlock after time expires
 * - Manual admin unlock
 * - Failed attempt counter reset on successful login
 *
 * @group security
 * @group critical
 * @group integration
 */
class ProgressiveLockoutTest extends IntegrationTestCase
{
    protected AccountLockoutService $lockoutService;

    protected function setUp(): void
    {
        parent::setUp();

        // Initialize the lockout service
        $this->lockoutService = app(AccountLockoutService::class);

        // Create Super Admin role to prevent notification errors
        \Spatie\Permission\Models\Role::firstOrCreate([
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null,
        ]);
    }

    // ============================================================
    // LOCKOUT THRESHOLD TESTS (5 TIERS)
    // ============================================================

    #[Test]
    public function lockout_triggered_at_3_attempts_for_5_minutes()
    {
        // ARRANGE: User with 3 failed attempts
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 3 failed attempts
        for ($i = 0; $i < 3; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Check and apply lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Lockout created with 5 minute duration
        $this->assertNotNull($lockout);
        $this->assertEquals(3, $lockout->attempt_count);
        $this->assertEquals('progressive', $lockout->lockout_type);
        $this->assertNotNull($lockout->unlock_at);

        // Verify 5 minute lockout (allow 1 second variance)
        $expectedUnlockTime = now()->addMinutes(5);
        $this->assertTrue(
            abs($lockout->unlock_at->timestamp - $expectedUnlockTime->timestamp) <= 1,
            'Lockout duration should be 5 minutes for 3 attempts'
        );

        // ASSERT: Notification sent
        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    #[Test]
    public function lockout_triggered_at_5_attempts_for_15_minutes()
    {
        // ARRANGE: User with 5 failed attempts
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 5 failed attempts
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Check and apply lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Lockout created with 15 minute duration
        $this->assertNotNull($lockout);
        $this->assertEquals(5, $lockout->attempt_count);

        // Verify 15 minute lockout (allow 1 second variance)
        $expectedUnlockTime = now()->addMinutes(15);
        $this->assertTrue(
            abs($lockout->unlock_at->timestamp - $expectedUnlockTime->timestamp) <= 1,
            'Lockout duration should be 15 minutes for 5 attempts'
        );

        // ASSERT: Notification sent
        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    #[Test]
    public function lockout_triggered_at_7_attempts_for_30_minutes()
    {
        // ARRANGE: User with 7 failed attempts
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 7 failed attempts
        for ($i = 0; $i < 7; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Check and apply lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Lockout created with 30 minute duration
        $this->assertNotNull($lockout);
        $this->assertEquals(7, $lockout->attempt_count);

        // Verify 30 minute lockout (allow 1 second variance)
        $expectedUnlockTime = now()->addMinutes(30);
        $this->assertTrue(
            abs($lockout->unlock_at->timestamp - $expectedUnlockTime->timestamp) <= 1,
            'Lockout duration should be 30 minutes for 7 attempts'
        );

        // ASSERT: Notification sent
        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    #[Test]
    public function lockout_triggered_at_10_attempts_for_1_hour()
    {
        // ARRANGE: User with 10 failed attempts
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 10 failed attempts
        for ($i = 0; $i < 10; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Check and apply lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Lockout created with 60 minute (1 hour) duration
        $this->assertNotNull($lockout);
        $this->assertEquals(10, $lockout->attempt_count);

        // Verify 60 minute lockout (allow 1 second variance)
        $expectedUnlockTime = now()->addMinutes(60);
        $this->assertTrue(
            abs($lockout->unlock_at->timestamp - $expectedUnlockTime->timestamp) <= 1,
            'Lockout duration should be 60 minutes (1 hour) for 10 attempts'
        );

        // ASSERT: Notification sent
        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    #[Test]
    public function lockout_triggered_at_15_attempts_for_24_hours()
    {
        // ARRANGE: User with 15 failed attempts
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 15 failed attempts
        for ($i = 0; $i < 15; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Check and apply lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Lockout created with 1440 minute (24 hour) duration
        $this->assertNotNull($lockout);
        $this->assertEquals(15, $lockout->attempt_count);

        // Verify 1440 minute (24 hour) lockout (allow 1 second variance)
        $expectedUnlockTime = now()->addMinutes(1440);
        $this->assertTrue(
            abs($lockout->unlock_at->timestamp - $expectedUnlockTime->timestamp) <= 1,
            'Lockout duration should be 1440 minutes (24 hours) for 15 attempts'
        );

        // ASSERT: Notification sent
        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    // ============================================================
    // PROGRESSIVE ESCALATION TESTS
    // ============================================================

    #[Test]
    public function lockout_duration_escalates_progressively_with_more_attempts()
    {
        // ARRANGE: User
        $user = $this->createUser(['email' => 'user@example.com']);

        // TEST: 4 attempts should use 3-attempt threshold (5 minutes)
        $this->createFailedAttempts($user->email, 4);
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');
        $this->assertNotNull($lockout);
        $this->assertEqualsWithDelta(5, now()->diffInMinutes($lockout->unlock_at), 0.02);

        // Clean up
        AccountLockout::truncate();
        FailedLoginAttempt::truncate();

        // TEST: 6 attempts should use 5-attempt threshold (15 minutes)
        $this->createFailedAttempts($user->email, 6);
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');
        $this->assertNotNull($lockout);
        $this->assertEqualsWithDelta(15, now()->diffInMinutes($lockout->unlock_at), 0.02);

        // Clean up
        AccountLockout::truncate();
        FailedLoginAttempt::truncate();

        // TEST: 8 attempts should use 7-attempt threshold (30 minutes)
        $this->createFailedAttempts($user->email, 8);
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');
        $this->assertNotNull($lockout);
        $this->assertEqualsWithDelta(30, now()->diffInMinutes($lockout->unlock_at), 0.02);
    }

    #[Test]
    public function no_lockout_triggered_below_minimum_threshold()
    {
        // ARRANGE: User with only 2 failed attempts (below 3 threshold)
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Create 2 failed attempts
        $this->createFailedAttempts($user->email, 2);

        // ACT: Check for lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: No lockout created
        $this->assertNull($lockout);

        // ASSERT: No notification sent
        Notification::assertNothingSent();
    }

    // ============================================================
    // NOTIFICATION TESTS
    // ============================================================

    #[Test]
    public function account_locked_notification_sent_on_lockout()
    {
        // ARRANGE: User
        $user = $this->createUser(['email' => 'user@example.com']);

        // ACT: Trigger lockout
        $this->createFailedAttempts($user->email, 3);
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: AccountLockedNotification sent
        Notification::assertSentTo($user, AccountLockedNotification::class, function ($notification) use ($lockout) {
            return $notification->lockout->id === $lockout->id;
        });
    }

    #[Test]
    public function account_unlocked_notification_sent_on_auto_unlock()
    {
        // ARRANGE: Create expired lockout
        $user = $this->createUser(['email' => 'user@example.com']);
        $lockout = AccountLockout::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'ip_address' => '127.0.0.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 3,
            'locked_at' => now()->subMinutes(10),
            'unlock_at' => now()->subMinutes(1), // Already expired
            'reason' => 'Test lockout',
        ]);

        // ACT: Run auto-unlock
        $this->lockoutService->unlockExpiredAccounts();

        // ASSERT: AccountUnlockedNotification sent
        Notification::assertSentTo($user, AccountUnlockedNotification::class, function ($notification) use ($lockout) {
            return $notification->lockout->id === $lockout->id &&
                   $notification->lockout->unlock_method === 'auto';
        });

        // ASSERT: Lockout marked as unlocked
        $lockout->refresh();
        $this->assertNotNull($lockout->unlocked_at);
        $this->assertEquals('auto', $lockout->unlock_method);
    }

    #[Test]
    public function account_unlocked_notification_sent_on_manual_unlock()
    {
        // ARRANGE: Active lockout
        $user = $this->createUser(['email' => 'user@example.com']);
        $admin = $this->createUser(['email' => 'admin@example.com']);

        $lockout = AccountLockout::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'ip_address' => '127.0.0.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 3,
            'locked_at' => now(),
            'unlock_at' => now()->addMinutes(5),
            'reason' => 'Test lockout',
        ]);

        // ACT: Admin unlocks account
        $this->lockoutService->unlockByAdmin($user->email, $admin);

        // ASSERT: AccountUnlockedNotification sent
        Notification::assertSentTo($user, AccountUnlockedNotification::class, function ($notification) use ($lockout) {
            return $notification->lockout->id === $lockout->id &&
                   $notification->lockout->unlock_method === 'admin';
        });

        // ASSERT: Lockout marked as unlocked
        $lockout->refresh();
        $this->assertNotNull($lockout->unlocked_at);
        $this->assertEquals('admin', $lockout->unlock_method);
    }

    // ============================================================
    // AUTO-UNLOCK MECHANISM TESTS
    // ============================================================

    #[Test]
    public function expired_lockouts_are_automatically_unlocked()
    {
        // ARRANGE: Multiple expired lockouts
        $user1 = $this->createUser(['email' => 'user1@example.com']);
        $user2 = $this->createUser(['email' => 'user2@example.com']);

        AccountLockout::create([
            'user_id' => $user1->id,
            'email' => $user1->email,
            'ip_address' => '127.0.0.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 3,
            'locked_at' => now()->subMinutes(10),
            'unlock_at' => now()->subMinutes(2),
            'reason' => 'Test lockout',
        ]);

        AccountLockout::create([
            'user_id' => $user2->id,
            'email' => $user2->email,
            'ip_address' => '192.168.1.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 5,
            'locked_at' => now()->subMinutes(20),
            'unlock_at' => now()->subMinutes(1),
            'reason' => 'Test lockout',
        ]);

        // ACT: Run auto-unlock
        $unlockedCount = $this->lockoutService->unlockExpiredAccounts();

        // ASSERT: Both accounts unlocked
        $this->assertEquals(2, $unlockedCount);

        // ASSERT: Both accounts no longer locked
        $this->assertFalse($this->lockoutService->isAccountLocked($user1->email));
        $this->assertFalse($this->lockoutService->isAccountLocked($user2->email));
    }

    #[Test]
    public function active_lockouts_are_not_unlocked_prematurely()
    {
        // ARRANGE: Active lockout (not expired)
        $user = $this->createUser(['email' => 'user@example.com']);

        AccountLockout::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'ip_address' => '127.0.0.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 3,
            'locked_at' => now(),
            'unlock_at' => now()->addMinutes(5), // Still active
            'reason' => 'Test lockout',
        ]);

        // ACT: Run auto-unlock
        $unlockedCount = $this->lockoutService->unlockExpiredAccounts();

        // ASSERT: No accounts unlocked
        $this->assertEquals(0, $unlockedCount);

        // ASSERT: Account still locked
        $this->assertTrue($this->lockoutService->isAccountLocked($user->email));
    }

    // ============================================================
    // MANUAL UNLOCK TESTS
    // ============================================================

    #[Test]
    public function admin_can_manually_unlock_account()
    {
        // ARRANGE: Locked account
        $user = $this->createUser(['email' => 'user@example.com']);
        $admin = $this->createUser(['email' => 'admin@example.com']);

        $this->createFailedAttempts($user->email, 3);
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        $this->assertTrue($this->lockoutService->isAccountLocked($user->email));

        // ACT: Admin unlocks
        $result = $this->lockoutService->unlockByAdmin($user->email, $admin);

        // ASSERT: Unlock successful
        $this->assertTrue($result);
        $this->assertFalse($this->lockoutService->isAccountLocked($user->email));

        // ASSERT: Lockout record updated
        $lockout->refresh();
        $this->assertNotNull($lockout->unlocked_at);
        $this->assertEquals('admin', $lockout->unlock_method);
    }

    #[Test]
    public function manual_unlock_fails_if_no_active_lockout()
    {
        // ARRANGE: No lockout exists
        $user = $this->createUser(['email' => 'user@example.com']);
        $admin = $this->createUser(['email' => 'admin@example.com']);

        // ACT: Try to unlock
        $result = $this->lockoutService->unlockByAdmin($user->email, $admin);

        // ASSERT: Unlock fails
        $this->assertFalse($result);
    }

    // ============================================================
    // FAILED ATTEMPT COUNTER RESET TESTS
    // ============================================================

    #[Test]
    public function failed_attempt_counter_resets_on_successful_login()
    {
        // ARRANGE: User with failed attempts
        $user = $this->createUser([
            'email' => 'user@example.com',
            'password' => bcrypt('correct-password'),
        ]);

        // Create failed attempts
        $this->createFailedAttempts($user->email, 2);

        // Verify attempts exist
        $attemptCount = FailedLoginAttempt::where('email', $user->email)
            ->where('attempted_at', '>=', now()->subHour())
            ->count();
        $this->assertEquals(2, $attemptCount);

        // ACT: Successful login clears attempts
        $this->lockoutService->clearFailedAttempts($user->email);

        // ASSERT: Failed attempts cleared
        $attemptCount = FailedLoginAttempt::where('email', $user->email)
            ->where('attempted_at', '>=', now()->subHour())
            ->count();
        $this->assertEquals(0, $attemptCount);
    }

    #[Test]
    public function lockout_check_respects_one_hour_time_window()
    {
        // ARRANGE: User with old failed attempts (outside 1-hour window)
        $user = $this->createUser(['email' => 'user@example.com']);

        // Create old attempts (2 hours ago)
        for ($i = 0; $i < 3; $i++) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now()->subHours(2),
            ]);
        }

        // ACT: Check for lockout
        $lockout = $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: No lockout (old attempts don't count)
        $this->assertNull($lockout);
    }

    // ============================================================
    // LOCKOUT STATE QUERIES
    // ============================================================

    #[Test]
    public function can_check_if_account_is_locked()
    {
        // ARRANGE: Locked account
        $user = $this->createUser(['email' => 'user@example.com']);

        // Account not locked initially
        $this->assertFalse($this->lockoutService->isAccountLocked($user->email));

        // Create lockout
        $this->createFailedAttempts($user->email, 3);
        $this->lockoutService->checkAndApplyLockout($user->email, '127.0.0.1');

        // ASSERT: Account is locked
        $this->assertTrue($this->lockoutService->isAccountLocked($user->email));
    }

    #[Test]
    public function can_get_remaining_lockout_time()
    {
        // ARRANGE: Locked account with 5 minute lockout
        $user = $this->createUser(['email' => 'user@example.com']);

        AccountLockout::create([
            'user_id' => $user->id,
            'email' => $user->email,
            'ip_address' => '127.0.0.1',
            'lockout_type' => 'progressive',
            'attempt_count' => 3,
            'locked_at' => now(),
            'unlock_at' => now()->addMinutes(5),
            'reason' => 'Test lockout',
        ]);

        // ACT: Get remaining time
        $remainingTime = $this->lockoutService->getRemainingLockoutTime($user->email);

        // ASSERT: Approximately 5 minutes remaining (allow 1 minute variance)
        $this->assertNotNull($remainingTime);
        $this->assertGreaterThanOrEqual(4, $remainingTime);
        $this->assertLessThanOrEqual(5, $remainingTime);
    }

    // ============================================================
    // HELPER METHODS
    // ============================================================

    /**
     * Helper to create failed login attempts
     */
    private function createFailedAttempts(string $email, int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            FailedLoginAttempt::create([
                'email' => $email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'TestAgent',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }
    }
}
