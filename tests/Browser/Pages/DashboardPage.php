<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class DashboardPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/dashboard';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/dashboard');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@userMenu' => '[data-dropdown-toggle], .user-menu, button[aria-label*="User"]',
            '@logout' => 'a[href*="logout"], button:contains("Logout"), form[action*="logout"] button',
            '@profile' => 'a[href*="profile"]',
            '@settings' => 'a[href*="settings"]',
        ];
    }

    /**
     * Logout the current user.
     */
    public function logout(Browser $browser): void
    {
        $browser->click('@userMenu')
            ->pause(200)
            ->click('@logout')
            ->pause(500);
    }
}
