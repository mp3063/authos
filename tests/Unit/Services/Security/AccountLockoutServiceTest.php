<?php

namespace Tests\Unit\Services\Security;

use App\Models\AccountLockout;
use App\Models\FailedLoginAttempt;
use App\Models\User;
use App\Notifications\AccountLockedNotification;
use App\Notifications\AccountUnlockedNotification;
use App\Services\Security\AccountLockoutService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

class AccountLockoutServiceTest extends TestCase
{
    use RefreshDatabase;

    private AccountLockoutService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new AccountLockoutService;
        Notification::fake();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_applies_lockout_when_threshold_exceeded(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create 5 failed attempts (should trigger 15-minute lockout)
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => $email,
                'attempted_at' => now()->subMinutes(30),
            ]);
        }

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $lockout = $this->service->checkAndApplyLockout($email, $ipAddress);

        $this->assertInstanceOf(AccountLockout::class, $lockout);
        $this->assertEquals($email, $lockout->email);
        $this->assertEquals('progressive', $lockout->lockout_type);
        $this->assertNotNull($lockout->unlock_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_apply_lockout_below_threshold(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create only 2 failed attempts (below threshold)
        for ($i = 0; $i < 2; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => $email,
                'attempted_at' => now()->subMinutes(30),
            ]);
        }

        $lockout = $this->service->checkAndApplyLockout($email, $ipAddress);

        $this->assertNull($lockout);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('lockoutDurationProvider')]
    public function it_applies_progressive_lockout_durations(int $attempts, int $expectedDuration): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        for ($i = 0; $i < $attempts; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => $email,
                'attempted_at' => now()->subMinutes(30),
            ]);
        }

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $lockout = $this->service->checkAndApplyLockout($email, $ipAddress);

        $this->assertNotNull($lockout);

        $actualDuration = now()->diffInMinutes($lockout->unlock_at);
        $this->assertEqualsWithDelta($expectedDuration, $actualDuration, 1);
    }

    public static function lockoutDurationProvider(): array
    {
        return [
            '3 attempts = 5 minutes' => [3, 5],
            '5 attempts = 15 minutes' => [5, 15],
            '7 attempts = 30 minutes' => [7, 30],
            '10 attempts = 60 minutes' => [10, 60],
            '15 attempts = 1440 minutes' => [15, 1440],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_locks_account_manually(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $lockout = $this->service->lockAccount(
            $email,
            $ipAddress,
            10,
            60,
            'admin_initiated'
        );

        $this->assertInstanceOf(AccountLockout::class, $lockout);
        $this->assertEquals('admin_initiated', $lockout->lockout_type);
        $this->assertEquals(10, $lockout->attempt_count);
        $this->assertNotNull($lockout->unlock_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_sends_notification_on_lockout(): void
    {
        $user = User::factory()->create(['email' => 'test@example.com']);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $this->service->lockAccount($user->email, '192.168.1.1');

        Notification::assertSentTo($user, AccountLockedNotification::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_if_account_is_locked(): void
    {
        $email = 'test@example.com';

        AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        $result = $this->service->isAccountLocked($email);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_account_not_locked_when_expired(): void
    {
        $email = 'test@example.com';

        AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->subHours(1), // Expired
            'unlocked_at' => null,
        ]);

        $result = $this->service->isAccountLocked($email);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_account_not_locked_when_unlocked(): void
    {
        $email = 'test@example.com';

        AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => now()->subMinutes(10), // Already unlocked
        ]);

        $result = $this->service->isAccountLocked($email);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_active_lockout(): void
    {
        $email = 'test@example.com';

        $created = AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        $lockout = $this->service->getActiveLockout($email);

        $this->assertNotNull($lockout);
        $this->assertEquals($created->id, $lockout->id);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_unlocks_account(): void
    {
        $email = 'test@example.com';
        $user = User::factory()->create(['email' => $email]);

        AccountLockout::factory()->create([
            'user_id' => $user->id,
            'email' => $email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        $result = $this->service->unlockAccount($email, 'auto');

        $this->assertTrue($result);

        $lockout = AccountLockout::where('email', $email)->first();
        $this->assertNotNull($lockout->unlocked_at);
        $this->assertEquals('auto', $lockout->unlock_method);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_sends_notification_on_unlock(): void
    {
        $user = User::factory()->create(['email' => 'test@example.com']);

        AccountLockout::factory()->create([
            'user_id' => $user->id,
            'email' => $user->email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        $this->service->unlockAccount($user->email);

        Notification::assertSentTo($user, AccountUnlockedNotification::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_false_when_unlocking_non_locked_account(): void
    {
        $email = 'nonexistent@example.com';

        $result = $this->service->unlockAccount($email);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_unlocks_by_admin(): void
    {
        $user = User::factory()->create(['email' => 'test@example.com']);
        $admin = User::factory()->create(['email' => 'admin@example.com']);

        AccountLockout::factory()->create([
            'user_id' => $user->id,
            'email' => $user->email,
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info')->twice();

        $result = $this->service->unlockByAdmin($user->email, $admin);

        $this->assertTrue($result);

        $lockout = AccountLockout::where('email', $user->email)->first();
        $this->assertEquals('admin', $lockout->unlock_method);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_auto_unlocks_expired_accounts(): void
    {
        $user1 = User::factory()->create(['email' => 'user1@example.com']);
        $user2 = User::factory()->create(['email' => 'user2@example.com']);

        // Create 2 expired lockouts
        AccountLockout::factory()->create([
            'user_id' => $user1->id,
            'email' => $user1->email,
            'unlock_at' => now()->subMinutes(10),
            'unlocked_at' => null,
        ]);

        AccountLockout::factory()->create([
            'user_id' => $user2->id,
            'email' => $user2->email,
            'unlock_at' => now()->subMinutes(5),
            'unlocked_at' => null,
        ]);

        // Create one that's not expired
        AccountLockout::factory()->create([
            'email' => 'user3@example.com',
            'unlock_at' => now()->addHours(1),
            'unlocked_at' => null,
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info')->times(3);
        Log::shouldReceive('error')->zeroOrMoreTimes();

        $count = $this->service->unlockExpiredAccounts();

        $this->assertEquals(2, $count);

        $this->assertNotNull(AccountLockout::where('email', $user1->email)->first()->unlocked_at);
        $this->assertNotNull(AccountLockout::where('email', $user2->email)->first()->unlocked_at);
        $this->assertNull(AccountLockout::where('email', 'user3@example.com')->first()->unlocked_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_remaining_lockout_time(): void
    {
        $email = 'test@example.com';

        AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->addMinutes(45),
            'unlocked_at' => null,
        ]);

        $remaining = $this->service->getRemainingLockoutTime($email);

        $this->assertNotNull($remaining);
        $this->assertEqualsWithDelta(45, $remaining, 1);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_null_remaining_time_for_unlocked_account(): void
    {
        $email = 'test@example.com';

        $remaining = $this->service->getRemainingLockoutTime($email);

        $this->assertNull($remaining);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_zero_for_expired_lockout(): void
    {
        $email = 'test@example.com';

        AccountLockout::factory()->create([
            'email' => $email,
            'unlock_at' => now()->subMinutes(10),
            'unlocked_at' => null,
        ]);

        $remaining = $this->service->getRemainingLockoutTime($email);

        $this->assertEquals(0, $remaining);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_failed_attempts_after_successful_login(): void
    {
        $email = 'test@example.com';

        // Create some recent failed attempts
        FailedLoginAttempt::factory()->count(5)->create([
            'email' => $email,
            'attempted_at' => now()->subMinutes(30),
        ]);

        // Create an old failed attempt (should not be deleted)
        FailedLoginAttempt::factory()->create([
            'email' => $email,
            'attempted_at' => now()->subHours(2),
        ]);

        $this->service->clearFailedAttempts($email);

        $this->assertEquals(1, FailedLoginAttempt::where('email', $email)->count());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_permanent_lockout(): void
    {
        $email = 'test@example.com';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $lockout = $this->service->lockAccount(
            $email,
            '192.168.1.1',
            0,
            null,
            'permanent'
        );

        $this->assertEquals('permanent', $lockout->lockout_type);
        $this->assertNull($lockout->unlock_at);
        $this->assertStringContainsString('permanently locked', $lockout->reason);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_lockout_without_user(): void
    {
        $email = 'nonexistent@example.com';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $lockout = $this->service->lockAccount($email, '192.168.1.1');

        $this->assertInstanceOf(AccountLockout::class, $lockout);
        $this->assertNull($lockout->user_id);
        $this->assertEquals($email, $lockout->email);
    }
}
