<?php

namespace Tests\Browser\Admin;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\FilamentDashboardPage;
use Tests\DuskTestCase;

class DashboardTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test admin can view dashboard.
     */
    public function test_admin_can_view_dashboard(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit(new FilamentDashboardPage)
                ->assertVisible('@navigation')
                ->assertSee('Dashboard');
        });
    }

    /**
     * Test dashboard displays widgets.
     */
    public function test_dashboard_displays_widgets(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin')
                ->pause(1000)
                ->assertSee('System Health')
                ->assertSee('Real-Time Metrics')
                ->assertSee('OAuth Flow Monitor')
                ->assertSee('Security Monitor');
        });
    }

    /**
     * Test navigation menu is functional.
     */
    public function test_navigation_menu_is_functional(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit(new FilamentDashboardPage)
                ->click('@users')
                ->waitForLocation('/admin/users', 5)
                ->assertPathIs('/admin/users');
        });
    }

    /**
     * Test widget auto-refresh functionality.
     */
    public function test_widget_auto_refresh_functionality(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin')
                ->pause(2000)
                ->assertSourceHas('wire:poll')
                ->pause(5000); // Wait for auto-refresh
        });
    }

    /**
     * Test dashboard responsive design.
     */
    public function test_dashboard_responsive_design(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            // Test mobile view
            $this->resizeMobile($browser);
            $browser->visit('/admin')
                ->pause(500)
                ->assertVisible('@navigation');

            // Test desktop view
            $this->resizeDesktop($browser);
            $browser->refresh()
                ->pause(500)
                ->assertVisible('@navigation');
        });
    }
}
