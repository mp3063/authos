<?php

namespace Tests\Browser\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\RegisterPage;
use Tests\DuskTestCase;

class RegistrationTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test user can view registration form.
     */
    public function test_user_can_view_registration_form(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new RegisterPage)
                ->assertSee('Register')
                ->assertVisible('@name')
                ->assertVisible('@email')
                ->assertVisible('@password')
                ->assertVisible('@passwordConfirmation')
                ->assertVisible('@submit');
        });
    }

    /**
     * Test user can register with valid data.
     */
    public function test_user_can_register_with_valid_data(): void
    {
        $this->browse(function (Browser $browser) {
            $email = 'newuser@example.com';
            $password = 'SecurePassword123!';

            $browser->visit(new RegisterPage)
                ->register('John Doe', $email, $password)
                ->waitForLocation('/dashboard', 5)
                ->assertPathBeginsWith('/dashboard')
                ->assertAuthenticated();

            $this->assertDatabaseHas('users', [
                'email' => $email,
                'name' => 'John Doe',
            ]);
        });
    }

    /**
     * Test registration fails with invalid email.
     */
    public function test_registration_fails_with_invalid_email(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new RegisterPage)
                ->register('John Doe', 'invalid-email', 'SecurePassword123!')
                ->pause(500)
                ->assertSee('email')
                ->assertPathIs('/register');
        });
    }

    /**
     * Test registration fails with short password.
     */
    public function test_registration_fails_with_short_password(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new RegisterPage)
                ->register('John Doe', 'test@example.com', '123')
                ->pause(500)
                ->assertSee('password')
                ->assertPathIs('/register');
        });
    }

    /**
     * Test registration fails with existing email.
     */
    public function test_registration_fails_with_existing_email(): void
    {
        $existingUser = $this->createTestUser([
            'email' => 'existing@example.com',
        ]);

        $this->browse(function (Browser $browser) use ($existingUser) {
            $browser->visit(new RegisterPage)
                ->register('New User', $existingUser->email, 'SecurePassword123!')
                ->pause(500)
                ->assertSee('email')
                ->assertPathIs('/register');
        });
    }

    /**
     * Test user can navigate to login from registration.
     */
    public function test_user_can_navigate_to_login_from_registration(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit(new RegisterPage)
                ->click('@login')
                ->waitForLocation('/login')
                ->assertPathIs('/login');
        });
    }
}
