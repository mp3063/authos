<?php

namespace Tests\Browser\Security;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\LoginPage;
use Tests\DuskTestCase;

class BruteForceProtectionTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    /**
     * Test account lockout after multiple failed login attempts.
     */
    public function test_account_lockout_after_multiple_failed_attempts(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            // Attempt 5 failed logins
            for ($i = 0; $i < 5; $i++) {
                $browser->visit(new LoginPage)
                    ->login($user->email, 'wrongpassword')
                    ->pause(500);
            }

            // 6th attempt should trigger lockout
            $browser->visit(new LoginPage)
                ->login($user->email, 'password123')
                ->pause(500)
                ->assertSee('locked')
                ->assertPathIs('/login');

            // Verify lockout in database
            $this->assertDatabaseHas('account_lockouts', [
                'user_id' => $user->id,
                'locked' => true,
            ]);
        });
    }

    /**
     * Test failed login attempts are tracked.
     */
    public function test_failed_login_attempts_are_tracked(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new LoginPage)
                ->login($user->email, 'wrongpassword')
                ->pause(500);

            $this->assertDatabaseHas('failed_login_attempts', [
                'user_id' => $user->id,
            ]);
        });
    }

    /**
     * Test rate limiting on login endpoint.
     */
    public function test_rate_limiting_on_login_endpoint(): void
    {
        $this->browse(function (Browser $browser) {
            // Attempt many logins rapidly
            for ($i = 0; $i < 15; $i++) {
                $browser->visit(new LoginPage)
                    ->login('test@example.com', 'password');
            }

            // Should see rate limit message
            $browser->pause(500)
                ->assertSee('Too many');
        });
    }

    /**
     * Test IP blocking after suspicious activity.
     */
    public function test_ip_blocking_after_suspicious_activity(): void
    {
        $this->browse(function (Browser $browser) {
            // Simulate multiple failed attempts from same IP
            for ($i = 0; $i < 10; $i++) {
                $browser->visit(new LoginPage)
                    ->login("user{$i}@example.com", 'wrongpassword')
                    ->pause(100);
            }

            // Next attempt should be blocked
            $browser->visit(new LoginPage)
                ->pause(500);

            // Check if IP is blocked
            $this->assertDatabaseHas('ip_blocklist', [
                'ip_address' => '127.0.0.1',
            ]);
        });
    }
}
