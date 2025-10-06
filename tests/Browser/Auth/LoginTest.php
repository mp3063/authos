<?php

namespace Tests\Browser\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\LoginPage;
use Tests\DuskTestCase;

class LoginTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    /**
     * Test user can view login form.
     */
    public function test_user_can_view_login_form(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new LoginPage)
                ->assertSee('Login')
                ->assertVisible('@email')
                ->assertVisible('@password')
                ->assertVisible('@submit')
                ->assertVisible('@forgotPassword');
        });
    }

    /**
     * Test user can login with valid credentials.
     */
    public function test_user_can_login_with_valid_credentials(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new LoginPage)
                ->login($user->email, 'password123')
                ->waitForLocation('/dashboard', 5)
                ->assertPathBeginsWith('/dashboard')
                ->assertAuthenticated();
        });
    }

    /**
     * Test login fails with invalid credentials.
     */
    public function test_login_fails_with_invalid_credentials(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new LoginPage)
                ->login('wrong@example.com', 'wrongpassword')
                ->pause(500)
                ->assertVisible('@errorMessage')
                ->assertPathIs('/login')
                ->assertGuest();
        });
    }

    /**
     * Test login fails with invalid password.
     */
    public function test_login_fails_with_invalid_password(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new LoginPage)
                ->login($user->email, 'wrongpassword')
                ->pause(500)
                ->assertVisible('@errorMessage')
                ->assertPathIs('/login');
        });
    }

    /**
     * Test remember me functionality.
     */
    public function test_remember_me_functionality(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new LoginPage)
                ->login($user->email, 'password123', true)
                ->waitForLocation('/dashboard', 5)
                ->assertAuthenticated();
        });
    }

    /**
     * Test user can navigate to forgot password.
     */
    public function test_user_can_navigate_to_forgot_password(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new LoginPage)
                ->click('@forgotPassword')
                ->waitForLocation('/forgot-password')
                ->assertPathBeginsWith('/forgot-password');
        });
    }

    /**
     * Test user can navigate to registration.
     */
    public function test_user_can_navigate_to_registration(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new LoginPage)
                ->click('@register')
                ->waitForLocation('/register')
                ->assertPathIs('/register');
        });
    }

    /**
     * Test account lockout after failed attempts.
     */
    public function test_account_lockout_after_failed_attempts(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            // Try to login with wrong password 5 times
            for ($i = 0; $i < 5; $i++) {
                $browser->visit(new LoginPage)
                    ->login($user->email, 'wrongpassword')
                    ->pause(500);
            }

            // 6th attempt should show lockout message
            $browser->visit(new LoginPage)
                ->login($user->email, 'password123')
                ->pause(500)
                ->assertSee('locked')
                ->assertPathIs('/login');
        });
    }
}
