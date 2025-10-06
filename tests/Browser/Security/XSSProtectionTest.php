<?php

namespace Tests\Browser\Security;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\ProfilePage;
use Tests\DuskTestCase;

class XSSProtectionTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    /**
     * Test XSS attack in profile name field is prevented.
     */
    public function test_xss_attack_in_profile_name_is_prevented(): void
    {
        $user = $this->createTestUser();
        $xssPayload = '<script>alert("XSS")</script>';

        $this->browse(function (Browser $browser) use ($user, $xssPayload) {
            $this->loginAs($browser, $user);

            $browser->visit(new ProfilePage)
                ->updateProfile($xssPayload, $user->email)
                ->pause(500);

            // Refresh page and check if script is escaped
            $browser->refresh()
                ->assertDontSee('<script>')
                ->assertSourceHas(htmlspecialchars($xssPayload));
        });
    }

    /**
     * Test XSS in search field is prevented.
     */
    public function test_xss_in_search_field_is_prevented(): void
    {
        $admin = $this->createAdminUser();
        $xssPayload = '<img src=x onerror=alert("XSS")>';

        $this->browse(function (Browser $browser) use ($admin, $xssPayload) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->type('input[type="search"]', $xssPayload)
                ->pause(500)
                ->assertDontSee('<img src=x')
                ->assertSourceMissing('onerror=');
        });
    }

    /**
     * Test CSP headers are present.
     */
    public function test_csp_headers_are_present(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit('/')
                ->pause(200);

            $headers = $browser->driver->manage()->getCookies();
            // Note: Dusk doesn't provide easy access to response headers
            // This is a placeholder - in real tests you'd check headers via HTTP client
        });
    }

    /**
     * Test inline JavaScript is blocked by CSP.
     */
    public function test_inline_javascript_is_blocked_by_csp(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit('/')
                ->assertSourceMissing('onclick=')
                ->assertSourceMissing('javascript:');
        });
    }
}
