<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class FilamentDashboardPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/admin';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/admin');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@navigation' => '.fi-sidebar-nav, [data-sidebar]',
            '@users' => 'a[href*="/admin/users"]',
            '@organizations' => 'a[href*="/admin/organizations"]',
            '@applications' => 'a[href*="/admin/applications"]',
            '@roles' => 'a[href*="/admin/roles"]',
            '@logs' => 'a[href*="/admin/authentication-logs"]',
            '@userMenu' => 'button[data-sidebar-toggle]',
            '@createButton' => 'button:contains("New"), button[data-action="create"]',
            '@searchInput' => 'input[type="search"]',
        ];
    }

    /**
     * Navigate to a resource.
     */
    public function navigateTo(Browser $browser, string $resource): void
    {
        $browser->click("@{$resource}")
            ->pause(500)
            ->waitForLocation("/admin/{$resource}");
    }
}
