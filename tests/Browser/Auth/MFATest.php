<?php

namespace Tests\Browser\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\MFASetupPage;
use Tests\Browser\Pages\ProfilePage;
use Tests\DuskTestCase;

class MFATest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test user can enable MFA.
     */
    public function test_user_can_enable_mfa(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $this->loginAs($browser, $user);

            $browser->visit(new ProfilePage)
                ->assertVisible('@enableMFA')
                ->click('@enableMFA')
                ->waitForLocation('/mfa/setup', 5);

            $browser->on(new MFASetupPage)
                ->assertVisible('@qrCode')
                ->assertVisible('@secretKey')
                ->assertVisible('@verificationCode');
        });
    }

    /**
     * Test MFA setup requires valid code.
     */
    public function test_mfa_setup_requires_valid_code(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $this->loginAs($browser, $user);

            $browser->visit('/mfa/setup')
                ->on(new MFASetupPage)
                ->verifyCode('000000') // Invalid code
                ->pause(500)
                ->assertVisible('@errorMessage');
        });
    }

    /**
     * Test user can disable MFA.
     */
    public function test_user_can_disable_mfa(): void
    {
        $user = $this->createTestUser([
            'mfa_enabled' => true,
            'mfa_secret' => 'test-secret',
        ]);

        $this->browse(function (Browser $browser) use ($user) {
            $this->loginAs($browser, $user);

            $browser->visit(new ProfilePage)
                ->assertVisible('@disableMFA')
                ->click('@disableMFA')
                ->pause(500)
                ->assertVisible('@enableMFA');

            $this->assertDatabaseHas('users', [
                'id' => $user->id,
                'mfa_enabled' => false,
            ]);
        });
    }

    /**
     * Test login with MFA requires code.
     */
    public function test_login_with_mfa_requires_code(): void
    {
        $user = $this->createTestUser([
            'mfa_enabled' => true,
            'mfa_secret' => 'test-secret',
        ]);

        $this->browse(function (Browser $browser) use ($user) {
            $browser->visit('/login')
                ->type('input[name="email"]', $user->email)
                ->type('input[name="password"]', 'password123')
                ->click('button[type="submit"]')
                ->pause(500)
                ->assertPathBeginsWith('/mfa/verify')
                ->assertVisible('input[name="code"]');
        });
    }
}
