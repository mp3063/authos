<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class PasswordResetPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/forgot-password';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/forgot-password');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@email' => 'input[name="email"]',
            '@submit' => 'button[type="submit"]',
            '@backToLogin' => 'a[href*="login"]',
            '@errorMessage' => '.alert-danger, [role="alert"]',
            '@successMessage' => '.alert-success',
        ];
    }

    /**
     * Request password reset.
     */
    public function requestReset(Browser $browser, string $email): void
    {
        $browser->type('@email', $email)
            ->click('@submit')
            ->pause(500);
    }
}
