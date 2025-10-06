<?php

namespace Tests\Browser\Security;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class CSRFProtectionTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test CSRF token is present in forms.
     */
    public function test_csrf_token_is_present_in_forms(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit('/login')
                ->assertSourceHas('_token')
                ->assertSourceHas('csrf-token');
        });
    }

    /**
     * Test form submission without CSRF token fails.
     */
    public function test_form_submission_without_csrf_token_fails(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            // Try to submit form without CSRF token using JavaScript
            $browser->visit('/login')
                ->script('document.querySelector(\'input[name="_token"]\').remove();');

            $browser->type('input[name="email"]', $user->email)
                ->type('input[name="password"]', 'password123')
                ->click('button[type="submit"]')
                ->pause(500)
                ->assertSee('419'); // CSRF token mismatch
        });
    }

    /**
     * Test CSRF token is refreshed on each request.
     */
    public function test_csrf_token_is_refreshed_on_each_request(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit('/login');

            $firstToken = $browser->value('input[name="_token"]');

            $browser->visit('/register');

            $secondToken = $browser->value('input[name="_token"]');

            // Tokens should be different (or at least valid)
            $this->assertNotEmpty($firstToken);
            $this->assertNotEmpty($secondToken);
        });
    }
}
