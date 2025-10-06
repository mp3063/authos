<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class OAuthAuthorizePage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/oauth/authorize';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/oauth/authorize');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@authorizeButton' => 'button[name="approve"], button:contains("Authorize"), button:contains("Allow")',
            '@denyButton' => 'button[name="deny"], button:contains("Deny"), button:contains("Cancel")',
            '@applicationName' => '.application-name, h1, h2',
            '@scopesList' => '.scopes, .permissions, ul',
            '@errorMessage' => '.alert-danger, [role="alert"]',
        ];
    }

    /**
     * Authorize the application.
     */
    public function authorize(Browser $browser): void
    {
        $browser->click('@authorizeButton')
            ->pause(500);
    }

    /**
     * Deny the application.
     */
    public function deny(Browser $browser): void
    {
        $browser->click('@denyButton')
            ->pause(500);
    }

    /**
     * Get the application name.
     */
    public function getApplicationName(Browser $browser): string
    {
        return $browser->text('@applicationName');
    }
}
