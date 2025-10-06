<?php

namespace Tests\Browser\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Password;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\PasswordResetPage;
use Tests\DuskTestCase;

class PasswordResetTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test user can view password reset request form.
     */
    public function test_user_can_view_password_reset_request_form(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new PasswordResetPage)
                ->assertSee('Reset Password')
                ->assertVisible('@email')
                ->assertVisible('@submit');
        });
    }

    /**
     * Test user can request password reset with valid email.
     */
    public function test_user_can_request_password_reset_with_valid_email(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new PasswordResetPage)
                ->requestReset($user->email)
                ->pause(500)
                ->assertVisible('@successMessage');
        });
    }

    /**
     * Test password reset fails with invalid email.
     */
    public function test_password_reset_fails_with_invalid_email(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new PasswordResetPage)
                ->requestReset('nonexistent@example.com')
                ->pause(500)
                ->assertSee('email');
        });
    }

    /**
     * Test user can navigate back to login from password reset.
     */
    public function test_user_can_navigate_back_to_login_from_password_reset(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new PasswordResetPage)
                ->click('@backToLogin')
                ->waitForLocation('/login')
                ->assertPathIs('/login');
        });
    }
}
