<?php

namespace Tests\Browser\Admin;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\FilamentLoginPage;
use Tests\DuskTestCase;

class FilamentLoginTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    /**
     * Test admin can view Filament login form.
     */
    public function test_admin_can_view_filament_login_form(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new FilamentLoginPage)
                ->assertVisible('@email')
                ->assertVisible('@password')
                ->assertVisible('@submit');
        });
    }

    /**
     * Test admin can login with valid credentials.
     */
    public function test_admin_can_login_with_valid_credentials(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $browser->visit(new FilamentLoginPage)
                ->login($admin->email, 'password123')
                ->waitForLocation('/admin', 10)
                ->assertPathBeginsWith('/admin')
                ->assertAuthenticated();
        });
    }

    /**
     * Test Filament login fails with invalid credentials.
     */
    public function test_filament_login_fails_with_invalid_credentials(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new FilamentLoginPage)
                ->login('wrong@example.com', 'wrongpassword')
                ->pause(500)
                ->assertPathIs('/admin/login')
                ->assertGuest();
        });
    }

    /**
     * Test non-admin user cannot access Filament.
     */
    public function test_non_admin_user_cannot_access_filament(): void
    {
        $user = $this->createTestUser(); // Regular user without admin role

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit(new FilamentLoginPage)
                ->login($user->email, 'password123')
                ->pause(1000)
                ->assertPathIs('/admin/login'); // Should stay on login page
        });
    }
}
